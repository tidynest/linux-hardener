# Next Development Session: Linux Hardener

---

## Current State (as of 2026-08-11)

**Read this first: the last release is v1.5.1 (2026-07-27) and a substantial
body of work on `main` is past it, none of it released.** No count is given
here on purpose: it changes with every commit, and the figure that used to
stand in this sentence was stale within days. Read it live with
`git rev-list --count --no-merges v1.5.1..main`. The version in the tree is
still `1.5.1`, so none of the work described in this section is in a build a
user can install. `CHANGELOG.md` `[Unreleased]` is the authoritative record of that work;
this section only orients. The bulk of it is defect repair proved on the five
test containers: firewall boot persistence (a ufw enable that never asked
systemd to want the unit at boot, and a Debian activity probe that read a
oneshot unit as a live firewall), configuration layered across `/etc` and
`/usr/etc`, SSH crypto directives read and written where sshd actually reads
them, kernel parameters that could not be read no longer counted as passes, and
the cross-distro suite gaining rollback-lifecycle sections plus a refusal to
accept a run that is not the size it declares.

**Open work is tracked as GitHub issues, not in this file.** Nineteen issues,
[#36 to #54](https://github.com/tidynest/linux-hardener/issues), were filed on
2026-08-01 covering everything known and unfixed; #18 and #19 predate them.
Most of that batch is closed and the list is not restated here, because it
moves and this file does not: read it live with `gh issue list`. Where a
heading below still describes an open item, it names its issue, and an issue
that is still open is not evidence the work is undone - grep for the thing it
says is missing first.

**The specs and plans this file cites under `docs/superpowers/` are a local
working area, not part of the repository.** Those paths are named so the
maintainer can find them on their own disk; they resolve nowhere in a clone.

One representative piece of that unreleased work, because several documents
link to it: the permissions plugin's vendor layer (`f008a10`). When
a critical path is absent from `/etc`, the scan now assesses the distribution's
copy under `/usr/etc` and reports a finding naming that file when its mode
violates the directive. Measured on openSUSE, `/etc/sudoers` does not exist and
`/usr/etc/sudoers` is mode 0444 against a required 0440, so a Critical control had
been passing on evidence nobody collected. The vendor file is never written,
because it is package-owned and a package update would revert the change, so
`apply` does nothing for such a path and `apply --dry-run` previews nothing about
it; the finding instead carries the `install` command that copies the file into
`/etc`, and the operator runs it. Documented for operators in
[guide/troubleshooting.md](guide/troubleshooting.md#scan-reports-a-permissions-finding-under-usretc-and-apply-changes-nothing).

The differential suite (`scripts/test/differential-suite.sh`, introduced in
v1.5.0 and described below) grew alongside it and keeps growing. It now pins how
many checks each block records, so an emptied table cannot shrink a run into a
pass. Do not quote a check total from this file: `expected_check_total` in that
script is the live count, and the comment above it traces how each block arrived
at its size. Issue #47 tracked extending the oracle to the remaining six
plugins; all eight are now in the compared set, two of them with a ceiling
stated in the oracle. The one fixture that was left, a container reaching the
pure-nftables path, now exists as `create-container.sh arch-nftables`: the same
Arch bootstrap with ufw left out, so nftables is the only backend the plugin
can select. `firewall_backend_kind` and `firewall_default_is_drop` gained their
nftables arms alongside it, in that order, because an oracle taught to
recognise a state no fixture produces is a check nothing exercises. **Neither
has been run**: building the container needs root.

**Everything below this line shipped in v1.5.0 or earlier.** v1.5.1 followed on
the same day, 2026-07-27, and is the current release: it made `scan --exit-code`
fail on an incomplete scan as well as on findings, removed `scan --compliance`
(a flag clap accepted and no code read), and fixed hardening destroying vendor
configuration on openSUSE. See `CHANGELOG.md` `[1.5.1]` for the operator
guidance that shipped with it.

The reversible-rollback fix landed in v1.5.0
(`303c4d0`) - `hardener rollback` (CLI, desktop and fleet) now snapshots the
current state before restoring a checkpoint, so a rollback is itself
reversible; see
`docs/superpowers/specs/2026-07-21-rollback-auto-snapshot-design.md`.

The desktop GUI redesign **merged into `main` as PR #25** (`6e861b7`) and is
content-complete (Phases 0-6, frontend-only - no backend, IPC or CLI
behaviour changed): a grouped left sidebar (Local: Dashboard, Analysis,
Hardening; Fleet: Hosts, Fleet Apply, Scheduler; plus a pinned Settings
area) replaces the old flat top navigation bar; the former Remote and Fleet
screens are merged into a single **Hosts** page (`/remote` now redirects
there); Fleet Apply is a staged Preview/Execute flow with a sticky summary
bar; Scheduler is a single-Save form over schedule presets; and a new
**Settings** page adds a seven-theme swatch grid (Midnight Teal, Fortress,
Sentinel, Command, Guardian, Daywatch, High Contrast) plus an About block.

Three security fixes shipped alongside it: rollback could delete account files
on a remote host, the PAM plugin could destroy a config it failed to read, and
password ageing was never applied while being reported as compliant. A new
differential test suite (`scripts/test/differential-suite.sh`) verifies
hardening against the system's own readers rather than against this tool's
parser, which is what caught the third one.

**v1.4.0 released** (2026-07-19) to GitHub + GitLab: the honesty, idempotency
and coherence arc on top of v1.3.2 - honest apply counts (only real changes
tallied; no-op reads "no changes needed"), idempotent state-aware apply across
all 8 plugins, honest unchecked reporting (privilege-blocked checks are per-plugin
"could not verify" entries, /boot vfat gets fstab guidance), deep scan that moves
the score, remote/SSH executor-session privilege probing with a PermitRootLogin
lockout guard and ad-hoc host validation, `checkpoint list --limit/--all`, and a
full documentation audit. AUR bump follows the tag.

**v1.3.2 released** (2026-07-18): six fixes surfaced by the first real local
apply runs - procfs sysctl writes, active-firewall-backend selection with ufw
rule mapping, idempotent audit rule reload with an immutable-config
reboot-required skip, per-plugin error surfacing in the desktop and CLI, and
desktop dropdown/skip-count polish. AUR bump follows the tag.

**v1.3.0 released** (2026-07-18) to GitHub + GitLab: RHEL 10 compliance
profiles, three new frameworks (SOC 2, NIST 800-171 r3, FedRAMP Moderate),
concurrent scan execution with a services false-PASS fix, the no-MAC apply
fix with a first-class skipped state, per-command Tauri ACLs, a static musl
Docker image, build identity in --version, and the docs/scripts/packaging
restructure. AUR bump follows the tag.

**v1.2.2 released** (2026-07-02) to GitHub + GitLab: a rollback data-loss fix
(0000-perm files like `/etc/shadow` could be deleted on rollback; account-database
paths were missing from the rollback allowlist) plus a cross-distro container
refresh (Debian 13 / Fedora 44 / Rocky 10 / openSUSE Leap 16.0 via podman-export,
validated 5/5 × 127). Public line: 1.0.5 → 1.2.0 → 1.2.1 → 1.2.2 → 1.3.0 → 1.3.1 → 1.3.2 → 1.4.0
(1.1.0 was cut in-tree but never published).

v1.2.0 shipped: multi-host batch CLI (`batch scan/report/apply/rollback`),
per-host history/trends/regression detection, scheduler regression alerts,
ISO/IEC 27001:2022 compliance framework, multi-framework mappings across all 8
plugins, CIS coverage completion (11 controls now Pass/Fail; `report --framework
cis` shows 6 `ManualReview`, down from 17), PAM/permissions assessment
improvements (faillock/pwhistory threshold comparison; shadow/gshadow
allowed-bits mask), SSH crypto hardening (KexAlgorithms/Ciphers/MACs incl. PQ),
remote-correct checkpoints, Fleet GUI (scan posture + apply/rollback), and polkit
DE test tooling. `cargo test --workspace` read **660 passed / 0 failed / 38
ignored** at the time, on a tree roughly a third the size of current `main`;
not a figure to quote against a run today.

### Key completed milestones (cumulative through v1.2.0):

- **All 13 audit bugs fixed** (BUG-01 through BUG-13)
- **All 7 infrastructure issues resolved** (INFRA-01 through INFRA-07)
- **Trait refactor complete**: `Config` unit struct deleted, `HardeningPlugin` trait now accepts `&PluginConfig`
- **Cross-distro validation**: 127-test suite passes on Arch, Debian, Fedora, Rocky Linux 9, openSUSE
- **Live testing fixes** (2026-02-23): checkpoint directory permissions, vfat detection, scan history, auditd reload
- **PluginConfig wiring complete** (2026-02-23): all 8 plugins consume directives/exceptions
- **GUI/CLI feature parity complete** (2026-02-24): scan filtering, checkpoint CRUD, report export, scan history, audit/compliance modes
- **Scheduler UI complete** (2026-02-24): schedule config, notification config, email/webhook, test notification
- **UI polish pass complete** (2026-02-24): side-by-side layouts, card standardisation, responsive fixes
- **Packaging infrastructure** (2026-02-25): AUR PKGBUILD, RPM spec, Debian packaging, systemd units, polkit policy
- **Test quality pass** (2026-02-25): 178+ assertion messages, 80+ println removed, net -422 lines
- **High Contrast theme** (2026-02-25): WCAG AAA accessibility theme (7:1+ contrast ratios)
- **Man page** (2026-02-25): `packaging/assets/hardener.1` troff man page for all commands
- **Security remediation** (2026-02-26): all 53 security findings resolved (see `docs/security/archive/2026-02-25-internal-audit/REMEDIATION_TRACKER.md`)
- **Code quality pass** (2026-02-27): 27 code quality findings fixed, shared helper extraction, 10 packaging fixes
- **Documentation** (2026-02-27): SECURITY.md updated, docs/guide/installation.md created for 5 distro families
- **v1.0.3 parallel test runners** (2026-02-28): parallel variants of the GUI and cross-distro runners (since merged into `--parallel` flags on the base scripts, 2026-07-18), `run-desktop-tests.sh`, `run-all-tests-parallel.sh`
- **v1.0.2 merged branches** (2026-02-28): `cli-ux-perfection` (CLI crash fixes, stderr routing, idempotent dirs, user-mode systemd) + `feature/desktop-testing-ux` (keyboard nav, ARIA, clipboard, TabBar migration, 95 desktop tests)
- **Desktop tests**: 43 UX tests + 46 functional tests + 29 Node.js tests, counted
  from the sources rather than from a run: **no dated run of any of the three is
  recorded anywhere in this repository**, which is what file-map.md says of the
  same figures and is the honest status of them
- **660 unit/integration tests pass**, clippy clean, native + WASM builds clean

### Trait refactor summary (commits `81c13ad`, `d029629`, `b87fb1c`):

- Core: deleted `Config`, trait methods accept `&PluginConfig`, `PluginManager` uses `&HardenerConfig`
- All 8 plugins updated to new trait signature
- SSH plugin is the **pilot**: fully consumes `config.directives` for overrides and `config.has_valid_exception()` for exemptions
- 35 test locations updated across 16 test files

### Live testing fixes (2026-02-23):

| Commit | Fix |
|--------|-----|
| `06c9ab4` | Checkpoint directory permissions, metadata-only snapshots, vfat chmod detection |
| `44ebe2f` | CLI scan persists results to history database |
| `5edece5` | Audit plugin uses `augenrules --load` instead of `systemctl restart auditd` |

### Infrastructure issues resolved:

| Issue | Description | Resolution |
|-------|-------------|------------|
| INFRA-01 | Uncommitted work | ✅ All committed |
| INFRA-02 | SSH auth to remotes | ✅ Resolved (user keeps SSH URLs) |
| INFRA-03 | Version mismatch 0.3.2→0.3.3 | ✅ Fixed (`14ad7f4`) |
| INFRA-04 | GUI/Tauri excluded from CI | ✅ WASM CI check job added (`fee6124`) |
| INFRA-05 | Overlapping planning docs | ✅ Consolidated (`795718b`) |
| INFRA-06 | Tauri CSP disabled | ✅ CSP + capabilities added (`1aefc69`) |
| INFRA-07 | Workspace dep inconsistencies | ✅ Centralised (`14ad7f4`) |

**Build status**: `cargo check`, `cargo check -p hardener-ui --target wasm32-unknown-unknown`, `cargo test`, and `cargo clippy` all pass clean.

---

## What's next (priority order)

> Refreshed 2026-08-01. Items are open unless marked Done. Anything still open
> here has a GitHub issue, named inline; the
> [issue tracker](https://github.com/tidynest/linux-hardener/issues) is
> the authoritative list and this section is the narrative around it.

### Done: GUI/UX redesign (shipped in v1.5.0)

Merged as PR #25 (`6e861b7`). Phases 0-6 covered the Dashboard, Analysis and
Hardening restyle, the Fleet cluster (Hosts, Fleet Apply, Scheduler) and the
new Settings page; every phase was final-reviewed and eyeballed clean across
all seven themes. The GUI/CLI/backend contract was unchanged throughout. See
"Current State" above.

**Done (issue #48, closed 2026-08-08):** the E2E Playwright suite under
`gui-tests/` was stale against the redesign (`remote.spec.js` targeted a screen
that no longer exists, there were no Hosts or Settings specs, and redesigned
selectors broke others) and has been rewritten against it, covering the Hosts
and Settings pages, the Fleet Apply acknowledgement gate and all ten compliance
frameworks. Two guards were added with it: `run-gui-tests.sh` refuses a `dist/`
older than the frontend source, and the runner refuses a container with no font,
both of which had previously let a run pass against the wrong interface. Do not
quote a test count from this file; read it with `npx playwright test --list`.
Two cases the rewrite deliberately left uncovered were filed rather than guessed
at, issues #135 and #136, and both have since closed.

### P0: Compliance assessment coverage (phase 2)

**Phase 1: Done.** Unassessed controls report `ManualReview` not a false `Pass`.

**Phase 2: Done.** All 8 plugins now tag findings with STIG, NIST 800-53,
PCI-DSS, HIPAA, GDPR and ISO 27001:2022 control IDs (sourced from
ComplianceAsCode/SSG and the project catalogues, cited inline) alongside CIS, so
every framework fails on insecure systems. Failure mode is safe: a wrong mapping
causes a false *fail*, never a false pass. Design notes:
[docs/plans/archive/2026-06-19-compliance-coverage-phase2.md](plans/archive/2026-06-19-compliance-coverage-phase2.md).

**Phase 3 (derive + Option B): Done.** Coverage is now per-control and
plugin-declared: each plugin exposes `coverage()`, aggregated by
`hardener_plugins::compliance_coverage()` and injected into `ReportGenerator`
(the framework-level `AUTOMATED_FRAMEWORKS`/`is_automated` API is gone). A
control the engine assesses reports `Pass`/`Fail` for *every* framework (Option
B); one it does not assess reports `ManualReview`. Non-CIS catalogues
(`stig.rs`/`nist.rs`/`pci.rs`/`hipaa.rs`/`gdpr.rs`) are deleted and derived from
coverage, so each report uses a single id scheme with no placeholder noise. CIS
and ISO 27001 keep their curated catalogues (full standard, unassessed controls →
`ManualReview`). Verified end-to-end (`hardener report --framework STIG`).

**Compliance: remaining follow-ups (not lost):**
- **HIPAA/GDPR confidence**: review done (2026-06-20). Inventoried all HIPAA/GDPR mappings (8 plugins) and SSG-cross-checked the questionable ones. SSH/PAM/audit/firewall/permissions/MAC/services sound; GDPR `TM-*` scheme + `Art.32(1)(a)` (encryption→SSH crypto only) consistent. **Fixed:** kernel cited HIPAA `164.312(c)(1)` (Integrity) on exploit-mitigation sysctls: re-cited the SSG-referenced ones (ASLR/`dmesg_restrict`/`suid_dumpable`) to `164.312(a)(1)` and dropped the unsourced ones (`kptr_restrict`/`ptrace_scope`/`protected_*links`). **Permissions/MAC alignment, done:** both already carried `164.312(a)(1)` alongside `(c)(1)`; the redundant `(c)(1)` is dropped so they match SSG's `164.312(a)` preference. Absence is locked in by regression assertions in both plugins' tests.
- **CIS catalogue hygiene**: done. `5.2.14`-`5.2.16` (strong Kex/Ciphers/MACs) are now in the curated `cis.rs`. Note: Option-B `Pass` visibility was *already* working for any plugin-emitted CIS id via the phase-3 coverage merge (the generator folds coverage into the catalogue for CIS too), the curated entries are for standard completeness, not to fix a missing `Pass`. The bare CIS `1.6.1` the kernel plugin emitted for `fs.protected_hardlinks/symlinks` has been **removed**: the upstream SSG rules carry no CIS reference (only NIST/STIG), so the mapping was unsourced and collided with the curated `1.6.1.1`-`1.6.1.4` MAC controls. Sourced NIST/STIG mappings retained.

### P1: SSH crypto-algorithm hardening (Done)

The SSH plugin now hardens `KexAlgorithms`/`Ciphers`/`MACs` including post-quantum
kex (`mlkem768x25519-sha256`, `sntrup761x25519-sha512`). It auto-detects host
support via `ssh -Q kex|cipher|mac` and writes only the intersection with a strong
allow-list (`select_algorithms`), so it can never set an unknown algorithm (no
lockout) or a weak one (no downgrade); empty intersection → leave host default.
`validate_sshd_config` runs `sshd -t -f <temp>` before any write/restart and
aborts on failure. Pure helpers are unit-tested with `MockExecutor`.

**Small follow-up (not lost):** consider an `#[ignore]` root integration test for
the full apply path (still flock-bound, see git history). (Obsolete `Protocol 2`
directive now removed.)

### P1: ISO/IEC 27001:2022 framework (Done)

`iso27001.rs` now defines the 93 Annex A:2022 controls across the 4 themes
(Organizational 37, People 8, Physical 14, Technological 34) with official clause
numbers and titles, wired into `frameworks::get_controls`. Plugin findings map to
the Technological controls (8.24 crypto, 8.5 auth, 8.20 networks, 8.15 logging,
8.9 config, 8.3 access), so ISO 27001 reports assess real state.

### P2: RHEL 10 compliance profiles (Done)

DISA RHEL 10 STIG V1R1 (2026-06-02) and CIS RHEL 10 v1.0.1 profile data now ship
in `profiles.rs` (`RHEL10_STIG`/`RHEL10_CIS`), keyed by canonical RHEL 8 rule id
and CIS section and wired into the catalogue via `ComplianceProfile::Rhel10`.
Distro detection already routes RHEL 10 through the Red Hat family. Shipped in
v1.3.0.

### P2: Multi-host SSH management

CLI batch-scan slice: **Done.** `hardener batch scan` scans many hosts
concurrently (`--all` / `--host` from the shared inventory, ad-hoc `--ssh`,
`--concurrency`), with a per-host + rollup report and tiered CI exit codes
(0 clean / 1 findings / 2 host or usage error). The inventory
(`~/.config/linux-hardener/hosts.toml`) is shared with the desktop GUI.

Per-host history persistence slice: **Done.** `batch scan` persists each host's
results to the scheduler history db keyed by host (inventory name, or
`user@host:port` for ad-hoc hosts), best-effort; the pool uses SQLite WAL for safe
concurrent writes. Read back with `history list --host <key>`. Spec/plan under
`docs/superpowers/`.

Per-host trend tracking slice: **Done.** `hardener history trends --host <key>`
derives a per-host timeline on query from the persisted sessions (no new table,
no stored score): completed scans oldest-first with per-severity counts, the
change in total findings, and a `better`/`worse`/`same` direction computed by
severity priority. `--format json` emits the points. Unit-tested direction logic
plus a live render against a real host.

Regression alerts slice: **Done (CLI).** `hardener history regressions [--host]`
compares each host's two newest completed scans and reports the ones whose latest
is worse (same severity-priority compare as trends), exiting `1` when any
regression is found so it can gate CI (`0` otherwise). Unit-tested detection.
The detection core (`find_regressions`) is reusable by a future scheduler-driven
alert; wiring regressions into the daemon's email/webhook notifications is the
remaining, larger half of "alerts".

Scheduler regression notifications slice: **Done.** The daemon notifies via the
configured email/webhook channels when a scheduled scan regresses against the
host's previous scan. `notify_mode` = `findings` (default) / `regression` /
`both`; measured at the `notify_min_severity` floor; self-deduping. Spec + plan
under `docs/superpowers/`.

Batch report slice: **Done.** `hardener batch report` assesses many hosts against
a compliance framework (`--framework`) or scenario preset (`--scenario`,
defaulting to `server`) concurrently and prints a fleet posture table (per
`(host, framework)`: score + pass/fail/manual/N-A counts) plus a per-framework
rollup. Tiered exit code (0 compliant / 1 failing control / 2 host error) gates
CI; `--format json` and `--output` supported. Reuses the `batch scan` engine
verbatim (connection, concurrency, isolation, history persistence). Spec/plan
under `docs/superpowers/`.

Remote-correct checkpoints slice: **Done.** Checkpoint capture and restore
now run through the active `SystemExecutor`, so `apply --ssh` and
`rollback --ssh` snapshot and restore the **remote** host rather than the
controller. Checkpoints are keyed by host; rollback refuses to restore one
host's checkpoint onto another. The executor abstraction (`SystemExecutor`,
`FileMetadata`, `CommandOutput`, `MockExecutor`) moved from `hardener-core`
into `hardener-common` (re-exported from core for source compatibility);
`SystemExecutor` gained `read_dir`, `FileMetadata` gained `uid`/`gid`.

Batch apply slice: **Done.** `hardener batch apply` applies hardening across
many hosts concurrently. Dry-run by default; `--execute` performs real changes.
A per-host privilege probe (uid 0 or passwordless `sudo`) gates `--execute` and
isolates non-privileged hosts as failed without aborting the rest. Each host
that executes receives an automatic host-keyed checkpoint and a best-effort
audit-log entry. Tiered exit: 0 all clean / 1 apply or validation failure /
2 connect, privilege or usage error. Flags mirror `batch scan`.

Batch rollback slice: **Done.** `hardener batch rollback` rolls back many hosts
concurrently to their latest per-plugin checkpoint
(`<plugin-id>-pre-apply`). Dry-run by default; `--execute` restores. Same
per-host privilege probe and isolation as `batch apply`; restores reuse the
host-keyed checkpoints (a checkpoint is never restored onto a different host) and
write a best-effort audit entry. Tiered exit: 0 all clean / 1 a checkpoint
restore failure / 2 connect, privilege or usage error.

Desktop fleet view (read-only): **Done.** A new **Fleet** page in the desktop
GUI scans several saved inventory hosts concurrently and shows each host's
severity posture (per-host critical/high/medium/low/info tallies, expandable to
that host's findings). Reuses the single-host scan path in-process; per-host
failure is isolated. Deferred follow-ups: ~~fleet apply/rollback in the GUI~~
(shipped 2026-06-28, see Fleet Apply page), ~~ad-hoc `--ssh` hosts~~ (shipped
2026-07-16, shared `RemoteHostProfile::from_target` parser, ad-hoc input on
both fleet pages, dry-run gate keys on the ad-hoc set), ~~live per-host
progress~~ (shipped 2026-07-16, `fleet-progress` Tauri event per completed
host, `listen_event` binding + pending/finished/failed list on the Fleet page),
~~per-host history in the GUI~~ (shipped 2026-07-16, `get_host_history` over
the scheduler db, history table + trend arrows in the fleet row expander; GUI
fleet scans remain in-memory, CLI batch/scheduled scans populate the history).
The last Fleet follow-up, **issue #50**, closed on 2026-08-04, and it shipped by
rejecting what it asked for: no `get_fleet_host_compliance_detail` IPC command
was added. `FleetFrameworkPosture` gained `controls: Vec<ControlOutcome>`
alongside the summary it already carried, so the per-host compliance count
drills into the verdicts in the payload the frontend already receives, and the
consumer joins them against the findings it already has. Emergency
per-host rollback remains available via `sudo hardener --ssh <host> rollback`.
Per-host CIS score columns plus a per-framework breakdown in the row expander
shipped 2026-06-24. (Superseded 2026-07 by the GUI/UX redesign: the
standalone Fleet page above is now the merged **Hosts** page - see
"Current State" above.)

**Follow-up (from review): Done (2026-07-16, issue #17, `c86c116`):**
`finding_to_scan_finding` now persists `severity`/`category` via `Display`
(`"CRITICAL"`, `"File System"`) instead of Debug variant names. Decision on
existing rows: no migration, the only parser of the stored severity string
(`SeverityCounts::from_findings`) is case-insensitive and the category string
is never parsed back, so old Debug-cased rows remain readable; the difference
is cosmetic in `history show` for pre-fix sessions.

### P3: Docker container image (Done)

Shipped in v1.3.0: `packaging/docker/Dockerfile` builds the existing
`x86_64-unknown-linux-musl` static binary in a `rust:1.97-alpine` stage and copies
it into a `FROM scratch` runtime (binary only, no glibc), with usage notes in
`packaging/docker/README.md`. **scan/report read-only is the safe default**;
*apply* against the real host would need `--privileged` + host namespaces
(`--pid=host`, host `/etc`, `/sys`), which undercuts container isolation and is
documented as discouraged. Validated on the Arch host and recorded in
`docs/reference/distribution-validation.md` (§Docker Image Validation).

### P3: Deferred code cleanups (Done, 2026-07-16)

All three flags resolved (issue #21): the dead `shared_data` field on
`Context` is removed (`330cb5b`), the registry's read/write lock-poison
handling shares one `lock_error` helper (`17181d5`), and a corrupted
`policy_exception` JSON column now surfaces `HardeningError::Database`
instead of being silently read as "no exception" (`33a87f6`, regression
test proven red→green).

### P3: Maintenance / currency

| Item | Detail | Status |
|------|--------|--------|
| Distro validation refresh | Container set recreated for the newer distro versions in v1.2.2: `scripts/containers/create-container.sh` now targets Debian 13 (Trixie), Fedora 44, Rocky 10 and openSUSE Leap 16.0 (Leap 15.6 EOL April 2026), validated 5/5. The `docs/reference/distribution-validation.md` results narrative still references the earlier v1.1.0 re-validation on the previous containers and is itself due an update. | ✅ Done |
| Cross-distro JSON-grep flake | **Root cause: the `sed` ANSI-strip in `run_test_output`** (NOT stderr-fold/capture, those fixes did not help). It piped captured output through `sed 's/ANSI//g'` before `grep`; under openSUSE's minimal-container locale that `sed` intermittently emitted nothing, masking fields that were present (proven: direct `grep -ac` matched 8/240/3 while `sed \| grep` missed). Dropped the pointless pre-strip (ANSI never splits matched tokens); now `grep -aqE`s the captured file directly, with a `diag:` line on the fail path. Suite green 125/125 × 5. | ✅ Done (837963b) |
| `tauri` 2.11.2 → 2.11.3 | Latest patch (2026-06-17); no CVE, routine bump | ✅ Done (lockfile, 2026-06-20) |
| Desktop crate compile fix | Tauri compliance commands ported to the phase-3 `ReportGenerator::new(config, coverage)` signature; `cargo check -p linux-hardener-desktop` clean | ✅ Done (2026-06-20) |
| External security audit | Third-party review; scope in [security/external-audit-scope.md](security/external-audit-scope.md) | ⬜ Open, issue #19 |
| Real desktop-environment polkit runs | GNOME/KDE/XFCE pkexec sessions; the tooling ships, the runs need live sessions | ⬜ Open, issue #18 |
| Release checklist for the next tag | The unreleased work needs a tagged release; the man page also has no `/usr/etc` text. **No count here**, per this file's own opening rule: the figure read 189 from 2026-08-02 and was 778 by 2026-08-18. Read it live with `git rev-list --count --no-merges v1.5.1..main` | ⬜ Open, issue #53 |
| Performance optimisation | Scan speed improvements; `scan --timings` shipped | ✅ Done, issue #20 closed 2026-07-17 |

---

## Completed in earlier sessions

### 1. PluginConfig wiring: COMPLETED (2026-02-23)

All 8 plugins now fully consume `PluginConfig` directives and exceptions. Two families:

- **Value-override** (directives + exceptions): SSH, Kernel, Firewall, PAM, Permissions
- **Binary** (exceptions only): Services, Audit, MAC

| Plugin | Commit | Status |
|--------|--------|--------|
| SSH (pilot) | `d029629` | Done |
| Kernel | `ca53286` | Done |
| Firewall | `820f406` | Done |
| PAM | `95bf62b` | Done |
| Services | `f97e33b` | Done |
| Permissions | `d01432a` | Done |
| Audit | `2ec356a` | Done |
| MAC | `ef0f8f6` | Done |

### 2. GUI/CLI Feature Parity (v0.4.0): COMPLETED (2026-02-24)

See `docs/plans/archive/2026-02-24-gui-cli-parity.md`: all 6 phases complete.

| Phase | Feature | Priority | Status |
|-------|---------|----------|--------|
| Phase 1 | Dry-run preview | P0 | Done |
| Phase 2 | Scan filtering (severity dropdown, plugin selection) | P0 | Done |
| Phase 3 | Checkpoint management (create/delete) | P1 | Done |
| Phase 4 | Report export (format selection, file save) | P1 | Done |
| Phase 5 | Scan history tab | P2 | Done |
| Phase 6 | Audit/compliance mode toggles | P2 | Done |

### 3. Remaining polish items

| Item | Source | Priority | Status |
|------|--------|----------|--------|
| ~~JSON output for `checkpoint rollback` command~~ | ~~ROADMAP.md v0.3.2 H~~ | Done | `5167e5a` |
| ~~Polkit policy file for nicer dialog text~~ | ~~ROADMAP.md v0.3.2 H~~ | Done | 2026-02-25 |
| ~~High Contrast theme (WCAG AAA)~~ | ~~ROADMAP.md v0.3.2 C~~ | Done | 2026-02-25 |
| ~~Extract inline tests out of their source files~~ | ~~ROADMAP.md tech debt~~ | Done | 2026-08-01, issue #49: every one of the ten crates split, no source file in `crates/` or `src-tauri/src` holds an inline `#[cfg(test)]` block. The destination was a child module in its own file, not `tests/` |
| AUR/deb/rpm package building & upload | ROADMAP.md v1.0.0 | Medium | Specs ready |

### 4. v1.0.0 production readiness

| Item | Priority | Status |
|------|----------|--------|
| Security audit (internal: 53/53 complete) | Critical | Done, third-party review pending |
| Package distribution (deb, rpm, AUR) | High | Specs ready, build scripts created |
| Comprehensive user documentation | High | Man page + docs/guide/installation.md done |
| Performance optimisation | Medium | Done, issue #20 |

---

## Project Summary

**Linux Hardener** is a comprehensive Linux security automation tool written in Rust:

- **11 Crates** (10 core + 1 Tauri app)
- **8 Security Plugins**: Kernel, SSH, Firewall, PAM, Services, Audit, Permissions, MAC
- **1599 Passing Tests** (plus 43 ignored: root-, SSH- or backend-gated), measured
  2026-08-04 with `cargo test --workspace --no-fail-fast`; re-measure before
  quoting it, this number moves most weeks
- **Multi-Distribution Support**: Debian, Red Hat, Arch, SUSE families
- **Current Version**: 1.5.1 (code, tag and repo packaging; AUR bump follows the
  tag). `main` is a long way past that tag and unreleased. **No count here**,
  per this file's own opening rule: the pair read "189 commits, 178 excluding
  merges" from 2026-08-02 and measured 819 and 778 on 2026-08-18. Read it live
  with `git rev-list --count --no-merges v1.5.1..main`
- **WASM Support**: GUI frontend compiles to `wasm32-unknown-unknown`

For version history and detailed feature tracking, see [ROADMAP.md](ROADMAP.md).
For coding standards, workflow, and conventions, see [CONTRIBUTING.md](../CONTRIBUTING.md).

---

## Codebase Architecture

### Workspace Structure

```
/home/bakri/RustroverProjects/linux-system-hardener/
├── Cargo.toml (workspace root)
├── .cargo/config.toml       # WASM rustflags for getrandom
├── crates/
│   ├── hardener-types/      # WASM-compatible shared type definitions
│   ├── hardener-cli/        # CLI interface (entry point)
│   ├── hardener-core/       # Core scanning/execution engine
│   ├── hardener-plugins/    # 8 security hardening plugins
│   ├── hardener-scheduler/  # Daemon for scheduled scanning
│   ├── hardener-state/      # Checkpoint/audit trail (Ed25519 signed)
│   ├── hardener-compliance/ # PDF report generation (pdf feature)
│   ├── hardener-common/     # Shared utilities/errors
│   ├── hardener-distro/     # Distribution abstraction
│   └── hardener-ui/         # Leptos WASM frontend
├── src-tauri/               # Desktop application
├── docs/                    # Comprehensive documentation
└── scripts/                 # Utility scripts
```

### Crate Dependency Graph

```
hardener-cli (entry point)
  ├── hardener-core (engine)
  ├── hardener-plugins (scanners/appliers)
  ├── hardener-compliance (reporting)
  ├── hardener-scheduler (daemon)
  ├── hardener-state (audit trail)
  └── hardener-common (shared)

hardener-types (WASM-safe, no system deps)
  └── serde, chrono only

hardener-core
  ├── hardener-types
  ├── hardener-common
  └── hardener-state (optional)

hardener-plugins
  └── hardener-core

hardener-compliance
  ├── hardener-types
  ├── hardener-core (default-features = false)
  └── krilla (optional, pdf feature)

hardener-ui (WASM frontend)
  └── hardener-types (only!)

hardener-scheduler
  ├── hardener-core
  ├── hardener-plugins
  └── hardener-common
```

---

*This document is prepared for continuity between development sessions.*

**Last Updated**: 2026-08-18
