# Distribution Validation Results

**Last Updated**: 2026-08-07

This document tracks validation testing across supported Linux distributions.

**Last measured full cross-distro validation:** 2026-08-07, on containers
recreated immediately beforehand.
**Container set that ran:** Arch rolling, Debian 13 "Trixie", Ubuntu 24.04 LTS
"Noble", Fedora 44, Rocky Linux 10 (RHEL 10 binary-compatible) and openSUSE
Leap 16.0, all built by `scripts/containers/create-container.sh`.
**Container set that exists:** those same six. Ubuntu was added on 2026-08-07
and ran the same day, so the set that exists and the set that has run are now
the same set.
**Baseline validation:** hardener 0.3.3 (2026-02-23). The detailed per-distro
sections lower down are that baseline and still describe the container versions
of the time (Debian 12, Fedora 41, Rocky 9, openSUSE Leap 15.6).

> **Why the SUSE target moved:** **openSUSE Leap 15.x reached end of life in
> April 2026**, so the SUSE container is Leap 16.0. Family-based detection routes
> every release in each family (Debian, Red Hat, Arch, SUSE) identically, so the
> version a container happens to carry is the version validated and not the
> boundary of what is supported.

> **What is historical here.** The 2026-08-07 summary immediately below is the
> current reading. Everything under [v1.1.0 Re-validation](#v110-re-validation-2026-06-28)
> and every per-distro breakdown after it is a dated record kept for its failure
> analysis and its per-plugin detail, not a statement about the containers as they
> stand today.

---

## Summary

Measured 2026-08-07 by `scripts/test/release-readiness-root.sh`, which recreates
all six containers before every suite that uses one:

```bash
sudo ./scripts/test/release-readiness-root.sh
```

| Distribution | Family | Version | Test Date | Declared | Recorded | Pass | Fail | Skip | Status |
|--------------|--------|---------|-----------|----------|----------|------|------|------|--------|
| Arch Linux | Arch | Rolling | 2026-08-07 | 149 | 149 | 146 | 0 | 9 | VALIDATED |
| Debian | Debian | 13 (Trixie) | 2026-08-07 | 149 | 149 | 146 | 0 | 9 | VALIDATED |
| Ubuntu | Debian | 24.04 LTS (Noble) | 2026-08-07 | 149 | 149 | 146 | 0 | 9 | VALIDATED |
| Fedora | Red Hat | 44 | 2026-08-07 | 149 | 149 | 146 | 0 | 9 | VALIDATED |
| Rocky Linux | Red Hat | 10 | 2026-08-07 | 149 | 149 | 146 | 0 | 9 | VALIDATED |
| openSUSE | SUSE | Leap 16.0 | 2026-08-07 | 149 | 149 | 146 | 0 | 9 | VALIDATED |

The differential suite ran the same day on the same six: arch 86 of 86 with 10
unaskable, and the other five 88 of 88 with 8 unaskable. Arch differs because two
further rows are unaskable there, not because anything failed.

Two suites in that run did not pass, and neither reading is about a distribution.
The package suite failed one check on all six, which was a `pipefail` and `grep -q`
SIGPIPE inversion in the harness rather than a product defect, fixed in `6a82a5b`
and re-measured on arch at 28 passed, 0 failed, 2 skipped. The GUI suite failed on
all six, for the stale Playwright suite on three and a container name-resolution
gap on the other three; both are recorded on issue #48.

> **All six distributions were identical on every column.** "Declared" is what
> `suite_section_sizes` in `scripts/test/full-test-suite.sh` says a run of this
> shape should record, and "Recorded" is what the run actually recorded;
> `require_expected_total` refuses a run where the two differ, and reports the
> refusal through the failure count so a short run cannot read as a pass in
> `test-results/summary.txt`.

> **Why passed plus failed does not reach the recorded total.** Three of the 149
> recorded checks are section 23 rows that are recorded and then skipped: the ssh
> plugin's apply has nothing to do on a host sections 13 to 15 have already
> hardened, so it takes no checkpoint and there is nothing of its own to roll
> back. That outcome is declared, not a fault. The other six of the nine skips
> are never recorded as checks at all. The full breakdown is under
> [Expected Container Skips](#expected-container-skips-9-per-distro).

> **The audit plugin's apply fails in a container, by design, on all six.**
> There is no auditd to reload, so `augenrules --load` and `systemctl restart
> auditd` both fail and the plugin reports the run unsuccessful having already
> written `/etc/audit/rules.d/hardening.rules`. Section 12A applies that plugin
> deliberately and records its exit status as information rather than asserting
> on it; what it asserts on is the rules file existing, because that is the thing
> the rollback has to undo. Section 14 skips the same apply instead of running
> it. A non-zero exit from `apply --plugin audit-hardening` inside a container is
> the correct reading of the host, not a defect in the tool.

> **Note on family coverage:** Each validated distribution covers its entire family:
> - **Arch** covers Manjaro, EndeavourOS, Garuda
> - **Debian** covers Ubuntu, Linux Mint, Pop!_OS, elementary OS
> - **Fedora** covers RHEL, CentOS, AlmaLinux, Oracle Linux
> - **Rocky Linux** explicitly validates RHEL binary-compatible distributions (Rocky, AlmaLinux, CentOS Stream)
> - **openSUSE** covers SLES (SUSE Linux Enterprise Server)
>
> All distributions in a family map to the same `DistroFamily` enum and use identical hardener behaviour. The musl static binary works across all glibc versions.

---

## Docker Image Validation (2026-07-17)

The container image (`packaging/docker/Dockerfile`, `rust:1.97-alpine` build
stage, `FROM scratch` runtime carrying only the static musl binary) was built
from a clean tree and validated on the Arch host (Docker 29.6.1). The image
supports **scan and report only**; `apply` is unsupported in-container by
design and was deliberately not validated. Usage and the capability boundary:
`packaging/docker/README.md`.

| Item | Result |
|------|--------|
| `docker build -f packaging/docker/Dockerfile .` (repo root context) | OK: 5 m 40 s cold build, image 13.6 MB |
| Binary in image | `hardener 1.2.2`, static-pie, stripped |
| Documented scan (`--pid=host`, `/etc` `/var/log` `/usr/lib` read-only, `scan --format json`) | Exit 0, valid JSON, 19 findings |
| Same scan as `--user 1000:1000` | Identical to the root-in-container run (19 findings, same IDs) |
| Native run of the identical binary (extracted from image, non-root host user) | 20 findings |
| Scan with additional `-v /boot:/boot:ro -v /root:/root:ro` | 21 findings (= native 20 + audit degradation below) |
| `report --framework cis` in-container | Exit 0, 44 controls: 26 pass, 12 fail, 6 manual review |

**Finding-ID delta, container vs native (same binary, so the delta isolates
the container environment: exactly 3 IDs differ):**

- `permissions-hardening`: `perm--root` (0750) and `perm--boot` (0755) are
  absent in-container because `/root` and `/boot` sit outside the documented
  mounts; mounting them read-only restores both findings.
- `audit-hardening`: the container adds `audit_not_installed` because it
  cannot see the host's service manager (auditd is running on the host): the
  documented tool-unavailable degradation, to be read as *unverifiable
  in-container*, not as host truth.
- Every other finding ID is identical (kernel 4, mac 1, pam 10, ssh 3,
  firewall 0, services 0).

Remote `--ssh` operations are unavailable in the image (no ssh client binary).

---

## v1.1.0 Re-validation (2026-06-28)

The v1.1.0 musl static binary (`hardener 1.1.0`, ~13.6 MB, `static-pie`) was run
through the full CLI suite (`sudo ./scripts/test/run-cross-distro-tests.sh --apply`)
across all five containers. The GUI/Playwright suite was **subsequently re-run and
is green on all five distros** (113 tests across 9 specs, 2026-06-29, adds fleet,
fleet-apply, remote, and scheduler coverage). That GUI reading is a record of its
own date and has been superseded twice over: the specs were rewritten in August
and the current one is
[GUI Test Suite, 2026-08-08](#gui-test-suite-2026-08-08), green on all **six**
at 114 tests.

### Result (final, all harness fixes applied)

| Distro | Total | Pass | Fail | Skip | Exit |
|--------|-------|------|------|------|------|
| arch | 127 | 127 | 0 | 6 | 0 |
| debian | 127 | 127 | 0 | 6 | 0 |
| fedora | 127 | 127 | 0 | 6 | 0 |
| rhel (Rocky 9) | 127 | 127 | 0 | 6 | 0 |
| opensuse | 127 | 127 | 0 | 6 | 0 |

### Failure analysis: no product regressions

The validation ran in two passes; every failure was triaged directly against the
v1.1.0 binary, which emits all expected output correctly.

**Pass 1: stale test/doc drift (fixed).** `daemon status` failed on all 5 distros
because the suite (and the README) used the pre-v1.1.0 positional form
`daemon status 5`; v1.1.0 renamed it to `-l, --limit <N>`, so the old form errors
(`unexpected argument '5'`, exit 2). Fixed both suite invocations to `--limit 5`
and corrected the README. **Confirmed:** every `daemon status` test passes on all
5 distros.

**Pass 2: intermittent JSON-grep flake (resolved).** After the daemon fix, some
structure checks intermittently failed to find a field that was demonstrably present:
`"plugin_id"` (`--format json scan`), `report_framework` (`report --report-format
json`), `Checkpoints`/`cp_` (`checkpoint list`). Triage steps, each ruling out a
hypothesis:

- **Not the binary.** Run directly it emits every field every time (`plugin_id` ×8,
  `report_framework` ×3; 0/40 empty over a tight host loop).
- **Not stderr-fold, not capture truncation.** Switching `run_test_output` from a
  `$(eval … 2>&1)` capture to writing stdout to a temp file did not fix it. A
  failure-path probe then proved the field *was* in the captured file: a direct
  `grep -ac` counted 8 / 240 / 3 matches while the test's own check missed.
- **Root cause: the `sed` ANSI-strip pre-filter.** The check piped the file through
  `sed 's/ANSI//g'` before `grep`. Under openSUSE's minimal-container locale that
  `sed` intermittently emitted nothing (the differ between the passing `grep -ac`
  probe and the failing `sed | grep`); it was not reproducible on a host with full
  locales, even forcing `LC_ALL=C sed`.
- **Fix: delete the pre-strip.** ANSI colour codes wrap whole styled segments and
  never split the matched tokens, so the strip was unnecessary. `run_test_output`
  now runs `grep -aqE "$pattern" "$file"` directly on the captured file.

Product correctness, verified against the v1.1.0 binary directly:

```
hardener --format json scan                            | grep -c '"plugin_id"'        -> 8
hardener report --framework stig --report-format json  | grep -c report_framework     -> 3
hardener daemon status --limit 5                       | grep -c 'Database:'           -> 1  (exit 0)
hardener --format json daemon status --limit 5                                         -> exit 0, valid JSON
```

**Net:** both harness issues are fixed; the full suite is repeatably **127/127 on all
five distributions** (confirmed by a clean back-to-back single-distro and full run).
A self-diagnosing `diag:` line (exit/bytes/head) remains in `run_test_output`'s
failure path so any future capture anomaly is debuggable from the host log in one run.

---

## Automated Cross-Distro Testing

All validation results in this document are produced by a fully automated test
runner. One command runs the suite across every distribution in
`scripts/lib/common.sh`'s `DISTRO_ORDER`, collecting pass/fail/skip counts and
writing `test-results/summary.txt` (`test-results/differential-summary.txt`
under `--differential`, so the two suites do not overwrite each other). On a
booted container under `--apply` the suite records **149 checks** per
distribution. The results below are the six distributions that had been run
when they were measured.

### Running the Tests

```bash
# Build the musl static binary first
cargo build --release --target x86_64-unknown-linux-musl -p hardener-cli
cp target/x86_64-unknown-linux-musl/release/hardener target/release/hardener

# Recreate the containers. Sections 12A and 12B ask whether a rollback REMOVES
# something an apply created, which can only be asked of a host where it does
# not exist yet, and --apply hardens every container it touches.
for d in arch debian fedora rhel opensuse; do
    sudo ./scripts/containers/create-container.sh "$d" clean --no-confirm
    sudo ./scripts/containers/create-container.sh "$d"
done

# Run the full cross-distro validation (requires root for systemd-nspawn)
sudo ./scripts/test/run-cross-distro-tests.sh --apply --booted
```

`--apply` gates the destructive sections (12A, 12B, 13 to 16 and 23) that modify
system state inside containers. Without it, those sections do not run.

`--booted` boots each container under its own systemd with `--private-network`
instead of running the suite through `systemd-nspawn --pipe`. Section 12B needs
it: `systemctl mask` and `systemctl is-enabled` both require systemd as PID 1,
which `--pipe` does not provide, so under `--pipe` that section records its
precondition check and skips, naming the flag that would let it run. The private
network namespace is what makes a firewall apply safe to run at all: nspawn
grants `CAP_NET_ADMIN` only to a container that owns its own namespace, so the
rules land there and never in the host's netfilter.

**The suite declares its own size.** `suite_section_sizes` in
`scripts/test/full-test-suite.sh` states how many checks each section records for
a given combination of apply, booted and container, and `require_expected_total`
refuses a run that recorded a different number. The refusal is reported as a
counted failure and not through the exit status alone, because the runner writes
PASS into `summary.txt` for any distribution whose failure count is zero. A
section that quietly stopped recording would otherwise read as a shorter run
rather than as a fault.

### Test Infrastructure

- **Execution:** `systemd-nspawn --pipe` by default (non-interactive, no boot or login required), or `--boot --private-network` under `--booted`. The differential suite additionally gets `--private-network` on the `--pipe` path, because its kernel oracle needs the namespace and not the boot (#137); the full suite does not, since the flag also grants `CAP_NET_ADMIN` and no reading has been taken of that suite under it
- **Binary:** Single musl-linked static binary (~13MB) deployed to all containers
- **Safety:** 3-layer host protection:
  1. `systemd-nspawn` container isolation (filesystem, PID, network namespace)
  2. Container detection hard-exit in the hardener binary itself
  3. `--apply` flag gating for destructive operations
- **Container awareness:** A question this host cannot answer is declared unaskable in advance and skipped. A value that turns out undeterminable at runtime is a failure, never a skip
- **`/proc/sys` stays read-only in both execution modes**, so the `fs.*` and `kernel.*` parameters are out of reach and the kernel apply cannot touch the host. The `net.ipv4.*` parameters become writable inside the container's own namespace, which `--private-network` grants with or without `--boot`

### Expected Container Skips (9 per distro)

On an `--apply --booted` run every distribution skips exactly 9, and the same 9:

| # | Section | Test | Reason |
|---|---------|------|--------|
| 1 | 10 | Daemon start | Blocking command that would hang the test runner |
| 2 | 12 | Systemd install | No full systemd init (PID 1) in nspawn |
| 3 | 12 | Systemd status after install | Depends on systemd install |
| 4 | 12 | Systemd uninstall | Depends on systemd install |
| 5 | 14 | Apply audit-hardening | No kernel audit subsystem available in container |
| 6 | 14 | Apply mac-hardening | No SELinux/AppArmor kernel modules in container |
| 7 | 23 | Lifecycle: ssh-hardening's apply recorded the checkpoint it took | ssh takes no checkpoint where its apply has nothing to do |
| 8 | 23 | Lifecycle rollback: ssh-hardening | Follows from 7: there is no checkpoint of its own to roll back |
| 9 | 23 | Lifecycle: ssh-hardening findings after the rollback | Follows from 7: nothing was rolled back, so nothing to read |

Skips 1 to 6 are never recorded as checks. Skips 7 to 9 are recorded and then
skipped, which is why 146 passed and 0 failed out of 149 recorded rather than
149 passed. The runner now prints that split rather than leaving it to be
worked out: a clean run reads `149 declared, 146 passed, 0 failed, 9 skipped (3
declared without a verdict, 6 never declared)`, so the row adds up on the page.
It used to read `146/149 passed, 9 skipped` with no failure count at all, which
was read as three silent failures on a run that had none. The first number in
the bracket is derived as declared minus resolved, so it says what it measures
rather than what it is usually taken to mean: on a clean run those are the
skips taken after the check was announced, and a check that fell out of its
section without any verdict at all would land there too.

A `--differential` run reports a fifth number instead. Its checks reconcile by
construction, since a check it cannot determine is recorded as a failure rather
than as a skip, so the split above is nothing but zeroes; what moves between
fixtures is the count of rows declared unaskable and never asked, and the line
now names it. The arch reading of 2026-08-09, under `--pipe --private-network`:
`81 declared, 81 passed, 0 failed, 0 skipped, 13 unaskable and never asked`,
the 13 being the 7 parameters outside `/proc/sys/net`, the 3 services rows and
their pre-apply control on a fixture with no systemd, and the 2 `PASS_MIN_DAYS`
rows arch's shadow cannot carry. Both summary tables carry it as their `Unask` column beside
`NoVdt`, the checks a run declared without giving a verdict to.

`run-cross-distro-tests.sh --self-test` asserts the arithmetic, both the clean
and the failed line, the differential shape and the refusal of a call it cannot
read, and it needs no root, no container and no binary. It refuses any other
argument beside it rather than accepting one: it sits above the pre-flight and
above the line that creates the results directory, so a run asked for as
`--apply --booted --self-test` would otherwise exit 0 in a second having
entered no container, leaving the previous run's `summary.txt` to be read as
this run's.

Section 23 pairs each rollback with its own apply through
`ApplyResult::apply_checkpoint_id`, so a plugin whose apply took no checkpoint is
reported as such instead of being rolled back to some other apply's checkpoint.

Under `--pipe` rather than `--booted`, section 12B skips as well and the declared
size of the run changes accordingly. None of these skips indicates a deficiency
in the hardener: the subsystems are simply unavailable, or the plugin correctly
had nothing to do.

### Container Setup

Built by `scripts/containers/create-container.sh <distro>`, which is the
authority on what each image contains. Container names are stable and are relied
upon by the test runners.

| Distro | Container Name | Created With | Base Packages |
|--------|---------------|-------------|---------------|
| Arch Linux (rolling) | hardener-test | pacstrap | base, base-devel, openssh, audit, bluez, ufw, iptables, nftables, sudo, polkit, jq |
| Debian 13 (Trixie) | hardener-test-debian | debootstrap | systemd, openssh-server, auditd, bluez, ufw, iptables, nftables, sudo, polkitd, pkexec, procps, iproute2, jq |
| Ubuntu 24.04 LTS (Noble) | hardener-test-ubuntu | debootstrap | as Debian: both go through `bootstrap_apt_family` and install the same set, differing only in the suite, the archive, and that Ubuntu enables `universe` as well as `main` |
| Fedora 44 | hardener-test-fedora | podman image export | openssh-server, openssh-clients, audit, bluez, cracklib-dicts, firewalld, nftables, iptables, polkit, procps-ng, iproute, jq |
| Rocky Linux 10 | hardener-test-rhel | podman image export | as Fedora, but `iptables-nft` in place of `iptables` (Rocky 10 dropped the legacy package) |
| openSUSE Leap 16.0 | hardener-test-opensuse | podman image export | openssh-server, openssh-clients, audit, bluez, firewalld, nftables, iptables, polkit, procps, iproute2, jq |

**The Ubuntu container is built and has been run.** It joined `DISTRO_ORDER` on
2026-08-07, so `create-container.sh` builds six images and every runner iterates
six, and on the same day it ran the cross-distro suite under `--apply --booted`
and the differential suite, both passing with counts matching the other five.
The dated tables lower down this file that predate 2026-08-07 record
five-container runs and are left as taken.

All six containers additionally have:

- root/test and testuser/test with passwordless sudo
- SSH host keys generated with `ssh-keygen -A`, run under nspawn rather than
  chroot because ssh-keygen needs `/dev/urandom`. Without them `sshd -t` exits
  with "no hostkeys available", the ssh plugin correctly aborts every apply, and
  the whole plugin reads as broken for a reason that has nothing to do with it
- `sshd`, `auditd` and `bluetooth` enabled, not merely installed. Enabling is
  what makes installing count: the service-minimisation plugin raises a finding
  only for a unit that is enabled or active, so an installed but disabled
  `bluetooth.service` would leave the fixture with nothing to find. Leaving it to
  the packaging would not do either, since Debian enables a daemon on install
  where Arch does not and the six images would then disagree with each other.
  The enable step is called bare so a failure aborts creation rather than
  producing a container that builds cleanly and tests nothing

**Why bluez is on all six.** The service-minimisation plugin assesses five units
and every base image shipped with none of them, so the plugin had no subject
matter and an oracle over it could only read the same "nothing to report" on
every distribution. `bluetooth.service` is the fixture section 12B masks and then
asserts a rollback unmasks.

**Why `openssh-clients` is on the three podman-exported images.** It provides
`ssh -Q`, which is how the ssh plugin asks the host which algorithms it supports.
Without it the allow-list intersection is empty, the plugin skips all three
crypto directives as "leaving host default", and the crypto path is unreachable
on that distribution. These images carry
`/etc/ssh/sshd_config.d/40-redhat-crypto-policies.conf`, whose Ciphers and MACs
include values this tool's allow-list rejects, so this is the one fixture where
the drop-in override the plugin exists to beat can actually be produced.

**Why `cracklib-dicts` is on the two dnf-family images.** libpwquality's
dictionary check is on by default and fails closed: with no dictionary to load it
refuses every password, strong ones included, so a container without it cannot
answer whether a password policy works. Rocky's base image carries it and
Fedora's does not, a difference nobody chose that made one distribution's reading
incomparable with the other's.

---

## Test Categories (28 Sections, 149 Checks)

Counts are what each section declares for an `--apply --booted` run inside a
container, from `suite_section_sizes` in `scripts/test/full-test-suite.sh`. They
sum to 149. Sections run in the order listed, which is not numeric order:
19 runs last, and 12A and 12B run first inside the apply block.

| Section | Name | Checks | Description |
|---------|------|--------|-------------|
| 1 | Basic Commands | 11 | --version, --help, all subcommand help, plus `plugins` listing all 8 |
| 2 | Scan All Plugins | 10 | Full scan, each of the 8 plugins individually, and a multi-plugin scan |
| 3 | Scan Filters | 8 | All 5 severity levels, --audit, --exit-code, --quiet |
| 4 | Scan Output Formats | 5 | text and json rendered, csv and html refused at the parse, plus a JSON structure check |
| 5 | Reports All Frameworks | 7 | cis, stig, nist, pcidss, hipaa, gdpr, iso27001 |
| 6 | Reports All Scenarios | 7 | server, workstation, government, healthcare, financial, gdpr, all |
| 7 | Report Output Formats | 12 | text, json, csv, html and pdf for CIS, plus a PDF for each of the 7 frameworks |
| 8 | Dry-Run All Plugins | 9 | --dry-run for all 8 plugins, plus --all |
| 9 | Checkpoint Operations | 5 | list, create, list again, show, delete |
| 10 | Daemon Commands | 2 | status, run-once (daemon start is skipped) |
| 11 | History Commands | 5 | list, show, export, trends, regressions |
| 12 | Systemd Commands | 2 | generate, status (install/status/uninstall skipped in a container) |
| 12A | Rollback Undoes The Audit Apply | 7 | Apply audit hardening, roll it back, and assert on the filesystem that the rules file is gone, that `/etc/audit` lists exactly the paths it listed beforehand, and that the compiled rule set is back at its pre-apply line count (--apply only) |
| 12B | Rollback Undoes The Services Apply | 7 | Apply service minimisation, roll it back, and assert on the filesystem that the mask link is gone, that the unit is enabled again, and that `/etc/systemd/system` lists exactly the paths it listed beforehand (--apply only, and 1 check on an unbooted host, where the rest cannot be asked) |
| 13 | Apply Kernel | 1 | Apply kernel hardening |
| 14 | Apply Other Plugins | 5 | ssh, permissions, pam, firewall, services individually (audit and mac skipped in a container) |
| 15 | Apply --all | 1 | Apply all plugins at once |
| 16 | Rollback | 1 | Rollback to checkpoint |
| 17 | Global --format Flag | 3 | Global format flag with various commands |
| 18 | Error Handling | 4 | Invalid plugin, framework, checkpoint ID |
| 20 | Scan History Persistence | 3 | scan -> history list verification |
| 21 | History Filtering | 3 | --limit, --status filters |
| 22 | Plugin Filter Combinations | 4 | Short names, mixed, multi-plugin |
| 23 | Per-Plugin Lifecycle | 18 | Six checks each for kernel, ssh and permissions (--apply only). The host arrives hardened by sections 13 to 15, so each apply here is a second apply: the finding count must be unmoved by it, and unmoved by the rollback that follows |
| 24 | Config File Loading | 2 | Valid/invalid config file |
| 25 | Report Combinations | 2 | Framework + scenario + format combos |
| 26 | Flag Combinations | 3 | --quiet + --format, --audit + --format, multi-flag |
| 19 | Post-Apply Scan Verification | 2 | Final scan + compliance report. Runs last, and is not gated behind --apply |

**Why 12A and 12B come first inside the apply block, and must stay there.** Both
ask whether a rollback removes something an apply created, and that can only be
asked of a host where it does not exist yet. Section 15 applies every plugin, so
from that point on the audit rules file and the bluetooth mask link both exist,
their checkpoints capture them as present, and a rollback correctly restores them
rather than removing them. Moved after any of the applies, neither section fails:
each refuses to read at all and reports its precondition broken. Add new apply
sections after them, never before.

---

> **Note:** the detailed per-distro breakdowns below are the **v0.3.3 baseline**
> (2026-02-23). They remain representative of product behaviour; the v1.1.0
> re-validation and its failure analysis are in
> [v1.1.0 Re-validation](#v110-re-validation-2026-06-28) above.

## Arch Linux

**Test Date:** 2026-02-23
**Environment:** systemd-nspawn container
**Distro:** Arch Linux (Rolling)
**Binary:** hardener 0.3.3 (musl static build)

### Test Results

```
Total Tests:  123
Passed:       123
Failed:       0
Skipped:      6 (container environment limitations)
Pass Rate:    100%
```

### Test Categories

| Category | Tests | Result |
|----------|-------|--------|
| Basic Commands | all | All pass |
| Scan - All Plugins | 8 | All pass |
| Scan - Filters & Options | all | All pass |
| Scan - Output Formats | 4 | All pass |
| Reports - All Frameworks | 6 | All pass |
| Reports - All Scenarios | 7 | All pass |
| Reports - Output Formats | all | All pass |
| Dry-Run - All Plugins | 8 | All pass |
| Checkpoint Operations | all | All pass |
| Daemon Commands | all | All pass (1 skipped: daemon start) |
| History Commands | 3 | All pass |
| Systemd Commands | all | 3 skipped (install/status/uninstall) |
| Apply - Kernel Hardening | all | All pass |
| Apply - Other Plugins | all | All pass (2 skipped: audit, mac) |
| Apply --all | 1 | Pass |
| Rollback | 1 | Pass |
| Global --format Flag | 3 | All pass |
| Error Handling | all | All pass |
| Post-Apply Verification | 2 | All pass |
| Scan History Persistence | 3 | All pass |
| History Filtering | 3 | All pass |
| Plugin Filter Combinations | 4 | All pass |
| Per-Plugin Lifecycle | all | All pass (skips for audit, mac) |
| Config File Loading | 2 | All pass |
| Report Combinations | 2 | All pass |
| Flag Combinations | 3 | All pass |

### Plugin-Specific Results

| Plugin | Scan | Dry-Run | Apply | Notes |
|--------|------|---------|-------|-------|
| audit-hardening | Pass | Pass | Skipped | No kernel audit subsystem in container |
| firewall-hardening | Pass | Pass | Pass | ufw/nftables working |
| kernel-hardening | Pass | Pass | Pass | sysctl params applied |
| mac-hardening | Pass | Pass | Skipped | No AppArmor kernel modules in container |
| pam-hardening | Pass | Pass | Pass | PAM config updated |
| permissions-hardening | Pass | Pass | Pass | File perms corrected |
| service-minimisation | Pass | Pass | Pass | Services managed |
| ssh-hardening | Pass | Pass | Pass | sshd_config hardened |

### Compliance Reports Generated

| Framework | Status |
|-----------|--------|
| CIS Benchmark | Generated |
| STIG | Generated |
| NIST 800-53 | Generated |
| PCI-DSS | Generated |
| HIPAA | Generated |
| GDPR | Generated |

### Notes

- All 8 plugins functional (6 fully applied, 2 correctly skipped in container)
- Checkpoint create/show/delete working
- Rollback successfully restores state
- PDF generation working (krilla library)
- JSON/CSV/HTML output formats all valid
- Scan history persistence and filtering operational
- Config file loading validated

---

## Debian

**Test Date:** 2026-02-23
**Environment:** systemd-nspawn container (debootstrap)
**Distro:** Debian 12 (Bookworm)
**Binary:** hardener 0.3.3 (musl static build)

### Test Results

```
Total Tests:  123
Passed:       123
Failed:       0
Skipped:      6 (container environment limitations)
Pass Rate:    100%
```

### Test Categories

| Category | Tests | Result |
|----------|-------|--------|
| Basic Commands | all | All pass |
| Scan - All Plugins | 8 | All pass |
| Scan - Filters & Options | all | All pass |
| Scan - Output Formats | 4 | All pass |
| Reports - All Frameworks | 6 | All pass |
| Reports - All Scenarios | 7 | All pass |
| Reports - Output Formats | all | All pass |
| Dry-Run - All Plugins | 8 | All pass |
| Checkpoint Operations | all | All pass |
| Daemon Commands | all | All pass (1 skipped: daemon start) |
| History Commands | 3 | All pass |
| Systemd Commands | all | 3 skipped (install/status/uninstall) |
| Apply - Kernel Hardening | all | All pass |
| Apply - Other Plugins | all | All pass (2 skipped: audit, mac) |
| Apply --all | 1 | Pass |
| Rollback | 1 | Pass |
| Global --format Flag | 3 | All pass |
| Error Handling | all | All pass |
| Post-Apply Verification | 2 | All pass |
| Scan History Persistence | 3 | All pass |
| History Filtering | 3 | All pass |
| Plugin Filter Combinations | 4 | All pass |
| Per-Plugin Lifecycle | all | All pass (skips for audit, mac) |
| Config File Loading | 2 | All pass |
| Report Combinations | 2 | All pass |
| Flag Combinations | 3 | All pass |

### Plugin-Specific Results

| Plugin | Scan | Dry-Run | Apply | Notes |
|--------|------|---------|-------|-------|
| audit-hardening | Pass | Pass | Skipped | No kernel audit subsystem in container |
| firewall-hardening | Pass | Pass | Pass | ufw working (default on Debian) |
| kernel-hardening | Pass | Pass | Pass | sysctl params applied |
| mac-hardening | Pass | Pass | Skipped | No AppArmor kernel modules in container |
| pam-hardening | Pass | Pass | Pass | PAM config updated |
| permissions-hardening | Pass | Pass | Pass | File perms corrected |
| service-minimisation | Pass | Pass | Pass | Services managed |
| ssh-hardening | Pass | Pass | Pass | sshd_config hardened |

### Compliance Reports Generated

| Framework | Status |
|-----------|--------|
| CIS Benchmark | Generated |
| STIG | Generated |
| NIST 800-53 | Generated |
| PCI-DSS | Generated |
| HIPAA | Generated |
| GDPR | Generated |

### Build Notes

The standard glibc-linked binary from Arch Linux fails on Debian due to GLIBC version mismatch (Arch has 2.39, Debian 12 has 2.36). Solution: build a statically-linked musl binary:

```bash
# On Arch host (requires musl package)
cargo build --release --target x86_64-unknown-linux-musl -p hardener-cli
cp target/x86_64-unknown-linux-musl/release/hardener target/release/hardener
```

The musl binary is ~13MB and works across all glibc versions.

---

## Fedora

**Test Date:** 2026-02-23
**Environment:** systemd-nspawn container (dnf bootstrap)
**Distro:** Fedora 41
**Binary:** hardener 0.3.3 (musl static build)

### Test Results

```
Total Tests:  123
Passed:       123
Failed:       0
Skipped:      6 (container environment limitations)
Pass Rate:    100%
```

### Test Categories

| Category | Tests | Result |
|----------|-------|--------|
| Basic Commands | all | All pass |
| Scan - All Plugins | 8 | All pass |
| Scan - Filters & Options | all | All pass |
| Scan - Output Formats | 4 | All pass |
| Reports - All Frameworks | 6 | All pass |
| Reports - All Scenarios | 7 | All pass |
| Reports - Output Formats | all | All pass |
| Dry-Run - All Plugins | 8 | All pass |
| Checkpoint Operations | all | All pass |
| Daemon Commands | all | All pass (1 skipped: daemon start) |
| History Commands | 3 | All pass |
| Systemd Commands | all | 3 skipped (install/status/uninstall) |
| Apply - Kernel Hardening | all | All pass |
| Apply - Other Plugins | all | All pass (2 skipped: audit, mac) |
| Apply --all | 1 | Pass |
| Rollback | 1 | Pass |
| Global --format Flag | 3 | All pass |
| Error Handling | all | All pass |
| Post-Apply Verification | 2 | All pass |
| Scan History Persistence | 3 | All pass |
| History Filtering | 3 | All pass |
| Plugin Filter Combinations | 4 | All pass |
| Per-Plugin Lifecycle | all | All pass (skips for audit, mac) |
| Config File Loading | 2 | All pass |
| Report Combinations | 2 | All pass |
| Flag Combinations | 3 | All pass |

### Plugin-Specific Results

| Plugin | Scan | Dry-Run | Apply | Notes |
|--------|------|---------|-------|-------|
| audit-hardening | Pass | Pass | Skipped | No kernel audit subsystem in container |
| firewall-hardening | Pass | Pass | Pass | firewalld working |
| kernel-hardening | Pass | Pass | Pass | sysctl params applied |
| mac-hardening | Pass | Pass | Skipped | SELinux not functional in container |
| pam-hardening | Pass | Pass | Pass | PAM config updated |
| permissions-hardening | Pass | Pass | Pass | File perms corrected |
| service-minimisation | Pass | Pass | Pass | Services managed |
| ssh-hardening | Pass | Pass | Pass | sshd_config hardened |

### Compliance Reports Generated

| Framework | Status |
|-----------|--------|
| CIS Benchmark | Generated |
| STIG | Generated |
| NIST 800-53 | Generated |
| PCI-DSS | Generated |
| HIPAA | Generated |
| GDPR | Generated |

### Fedora-Specific Notes

1. **Kernel restrictions**: Container already had hardened defaults (`dmesg_restrict=1`, `kptr_restrict=2`).
2. **Firewalld**: Fedora uses firewalld by default (not ufw).
3. **SELinux**: Compiled into systemd but not functional in nspawn container.

---

## Rocky Linux

**Test Date:** 2026-02-23
**Environment:** systemd-nspawn container (podman export)
**Distro:** Rocky Linux 9
**Binary:** hardener 0.3.3 (musl static build)

### Test Results

```
Total Tests:  123
Passed:       123
Failed:       0
Skipped:      6 (container environment limitations)
Pass Rate:    100%
```

### Test Categories

| Category | Tests | Result |
|----------|-------|--------|
| Basic Commands | all | All pass |
| Scan - All Plugins | 8 | All pass |
| Scan - Filters & Options | all | All pass |
| Scan - Output Formats | 4 | All pass |
| Reports - All Frameworks | 6 | All pass |
| Reports - All Scenarios | 7 | All pass |
| Reports - Output Formats | all | All pass |
| Dry-Run - All Plugins | 8 | All pass |
| Checkpoint Operations | all | All pass |
| Daemon Commands | all | All pass (1 skipped: daemon start) |
| History Commands | 3 | All pass |
| Systemd Commands | all | 3 skipped (install/status/uninstall) |
| Apply - Kernel Hardening | all | All pass |
| Apply - Other Plugins | all | All pass (2 skipped: audit, mac) |
| Apply --all | 1 | Pass |
| Rollback | 1 | Pass |
| Global --format Flag | 3 | All pass |
| Error Handling | all | All pass |
| Post-Apply Verification | 2 | All pass |
| Scan History Persistence | 3 | All pass |
| History Filtering | 3 | All pass |
| Plugin Filter Combinations | 4 | All pass |
| Per-Plugin Lifecycle | all | All pass (skips for audit, mac) |
| Config File Loading | 2 | All pass |
| Report Combinations | 2 | All pass |
| Flag Combinations | 3 | All pass |

### Plugin-Specific Results

| Plugin | Scan | Dry-Run | Apply | Notes |
|--------|------|---------|-------|-------|
| audit-hardening | Pass | Pass | Skipped | No kernel audit subsystem in container |
| firewall-hardening | Pass | Pass | Pass | firewalld working |
| kernel-hardening | Pass | Pass | Pass | sysctl params applied |
| mac-hardening | Pass | Pass | Skipped | SELinux not functional in container |
| pam-hardening | Pass | Pass | Pass | PAM config updated |
| permissions-hardening | Pass | Pass | Pass | File perms corrected |
| service-minimisation | Pass | Pass | Pass | Services managed |
| ssh-hardening | Pass | Pass | Pass | sshd_config hardened |

### Compliance Reports Generated

| Framework | Status |
|-----------|--------|
| CIS Benchmark | Generated |
| STIG | Generated |
| NIST 800-53 | Generated |
| PCI-DSS | Generated |
| HIPAA | Generated |
| GDPR | Generated |

### Rocky Linux-Specific Notes

1. **RHEL binary compatibility**: Rocky Linux 9 is a 1:1 binary-compatible rebuild of RHEL 9. Validating on Rocky confirms compatibility with RHEL 9, AlmaLinux 9, and CentOS Stream 9.
2. **Firewalld**: Uses firewalld by default (same as Fedora/RHEL).
3. **SELinux**: Compiled into systemd but not functional in nspawn container.
4. **Container creation**: Built via `podman export` from an official Rocky Linux 9 container image.

---

## openSUSE

**Test Date:** 2026-02-23
**Environment:** systemd-nspawn container (zypper bootstrap)
**Distro:** openSUSE Leap 15.6
**Binary:** hardener 0.3.3 (musl static build)

### Test Results

```
Total Tests:  123
Passed:       123
Failed:       0
Skipped:      6 (container environment limitations)
Pass Rate:    100%
```

### Test Categories

| Category | Tests | Result |
|----------|-------|--------|
| Basic Commands | all | All pass |
| Scan - All Plugins | 8 | All pass |
| Scan - Filters & Options | all | All pass |
| Scan - Output Formats | 4 | All pass |
| Reports - All Frameworks | 6 | All pass |
| Reports - All Scenarios | 7 | All pass |
| Reports - Output Formats | all | All pass |
| Dry-Run - All Plugins | 8 | All pass |
| Checkpoint Operations | all | All pass |
| Daemon Commands | all | All pass (1 skipped: daemon start) |
| History Commands | 3 | All pass |
| Systemd Commands | all | 3 skipped (install/status/uninstall) |
| Apply - Kernel Hardening | all | All pass |
| Apply - Other Plugins | all | All pass (2 skipped: audit, mac) |
| Apply --all | 1 | Pass |
| Rollback | 1 | Pass |
| Global --format Flag | 3 | All pass |
| Error Handling | all | All pass |
| Post-Apply Verification | 2 | All pass |
| Scan History Persistence | 3 | All pass |
| History Filtering | 3 | All pass |
| Plugin Filter Combinations | 4 | All pass |
| Per-Plugin Lifecycle | all | All pass (skips for audit, mac) |
| Config File Loading | 2 | All pass |
| Report Combinations | 2 | All pass |
| Flag Combinations | 3 | All pass |

### Plugin-Specific Results

| Plugin | Scan | Dry-Run | Apply | Notes |
|--------|------|---------|-------|-------|
| audit-hardening | Pass | Pass | Skipped | No kernel audit subsystem in container |
| firewall-hardening | Pass | Pass | Pass | firewalld working |
| kernel-hardening | Pass | Pass | Pass | sysctl params applied |
| mac-hardening | Pass | Pass | Skipped | No AppArmor kernel modules in container |
| pam-hardening | Pass | Pass | Pass | PAM config updated |
| permissions-hardening | Pass | Pass | Pass | File perms corrected, but see the note below |
| service-minimisation | Pass | Pass | Pass | Services managed |
| ssh-hardening | Pass | Pass | Pass | sshd_config hardened |

**On permissions-hardening, three Passes do not mean every managed path was
corrected here.** openSUSE holds no `/etc/sudoers`, so before 2026-07-30 the
plugin reported nothing at all about `sudoers` and apply had nothing to do, which
is what "Pass" records. `/usr/etc/sudoers` was meanwhile sitting at 0444 against
a required 0440. `scan` now reports that as a Critical finding, and `apply` still
passes without correcting it, because the vendor file is never written and the
remediation is a copy into `/etc` that an operator has to make. On this
distribution a green apply and an outstanding Critical permission finding are the
expected, correct combination.

### Compliance Reports Generated

| Framework | Status |
|-----------|--------|
| CIS Benchmark | Generated |
| STIG | Generated |
| NIST 800-53 | Generated |
| PCI-DSS | Generated |
| HIPAA | Generated |
| GDPR | Generated |

### openSUSE-Specific Notes

1. **Reverse Path Filtering**: openSUSE defaults to `rp_filter=2` (loose mode). Hardener recommends `1` (strict mode) per CIS.
2. **Firewalld**: openSUSE uses firewalld by default (same as Fedora/RHEL).
3. **Kernel restrictions**: Container already had some hardened defaults (`dmesg_restrict=1`, `kptr_restrict=2`).

---

## Known Distribution Differences

| Feature | Arch | Debian | Red Hat (Fedora/Rocky) | SUSE |
|---------|------|--------|------------------------|------|
| Package Manager | pacman | apt | dnf | zypper |
| Firewall Default | ufw | ufw | firewalld | firewalld |
| Init System | systemd | systemd | systemd | systemd |
| SELinux | No | No | Yes | Optional |
| AppArmor | Optional | Yes | No | Yes |
| Default rp_filter | 1 (strict) | 1 (strict) | 1 (strict) | 2 (loose) |
| Default /etc/shadow mode | 0600 | 0640 | 0000 | 0640 |
| Audit Reload | augenrules --load | augenrules --load | augenrules --load | augenrules --load |

The shadow row is why `permissions-hardening` measures `/etc/shadow` and
`/etc/gshadow` against an allowed-bits mask rather than an exact mode: none of
those four values sets a bit outside 0640, so all four are already compliant and
the tool deliberately leaves them alone. An equality comparison would have
reported a defect on three of the five containers against a tool behaving
exactly as designed. The modes were read with `stat -c %a` by the permissions
oracle in `scripts/test/differential-suite.sh` on the five recreated containers,
2026-07-30.

SUSE's vendor layer also changes what an absent path means for a permission
check. openSUSE reserves `/etc` for administrator overrides and ships its own
copy under `/usr/etc`, and on that container `/etc/sudoers` does not exist while
`/usr/etc/sudoers` does, at mode 0444 against a directive requiring 0440: the
file in force is world-readable although `/etc` holds nothing. `scan` therefore
reads the vendor copy wherever `/etc` is empty and reports what it finds there,
keyed on the `/etc` path so one control has one id on every distribution. It
never writes `/usr/etc`, so the remediation named is an install into `/etc`.
`/etc/gshadow` is absent from both layers on that same container and stays
silent, which is the honest answer for a file the host does not have.

---

## Reproducing These Results

To reproduce the full cross-distro validation from scratch:

1. **Set up containers** -- `scripts/containers/create-container.sh <distro>` creates each one, at `/var/lib/machines/<container name>`:
   - `sudo ./scripts/containers/create-container.sh arch` (Arch rolling via pacstrap)
   - `sudo ./scripts/containers/create-container.sh debian` (Debian 13 Trixie via debootstrap)
   - `sudo ./scripts/containers/create-container.sh fedora` (Fedora 44 via podman export)
   - `sudo ./scripts/containers/create-container.sh rhel` (Rocky Linux 10 via podman export)
   - `sudo ./scripts/containers/create-container.sh opensuse` (openSUSE Leap 16.0 via podman export)

   **Recreate rather than reuse.** `--apply` hardens every container it touches
   and nothing in the suite undoes the audit apply section 15 performs, so a
   second `--apply` run in the same container cannot ask sections 12A and 12B
   their question and both will report their precondition broken. Remove first
   with `sudo ./scripts/containers/create-container.sh <distro> clean
   --no-confirm`.

2. **Build the musl static binary**:
   ```bash
   cargo build --release --target x86_64-unknown-linux-musl -p hardener-cli
   cp target/x86_64-unknown-linux-musl/release/hardener target/release/hardener
   ```

3. **Run the cross-distro test suite**:
   ```bash
   sudo ./scripts/test/run-cross-distro-tests.sh --apply --booted
   ```

4. **Review results** -- The runner writes `test-results/summary.txt` and a per-distro `test-results/<distro>.log`, and prints the same table to stdout.

---

## GUI Testing (Web UI -- Playwright)

In addition to CLI testing, the Web UI is validated with Playwright across all 5 distributions.

> **The GUI figures in this section are older than the CLI ones above.** The last
> recorded run is 2026-06-29, on the previous container versions, and the
> Playwright suite has not been re-run since the desktop redesign landed. The
> spec inventory below is read off the tree and is current; the pass counts are
> not. Treat this section as a record, not as a present-tense claim.

### Summary

| Distribution | Family | Version | Test Date | Tests | Pass | Fail | Status |
|--------------|--------|---------|-----------|-------|------|------|--------|
| Arch Linux | Arch | Rolling | 2026-02-23 | 84 | 84 | 0 | VALIDATED (v0.3.3 baseline) |
| Debian | Debian | 12 (Bookworm) | 2026-02-23 | 84 | 84 | 0 | VALIDATED (v0.3.3 baseline) |
| Fedora | Red Hat | 41 | 2026-02-23 | 84 | 84 | 0 | VALIDATED (v0.3.3 baseline) |
| Rocky Linux | Red Hat | 9 | 2026-02-23 | 84 | 84 | 0 | VALIDATED (v0.3.3 baseline) |
| openSUSE | SUSE | Leap 15.6 | 2026-02-23 | 84 | 84 | 0 | VALIDATED (v0.3.3 baseline) |

The suite has grown since that baseline, and has since been rewritten. The
current reading is under
[GUI Test Suite, 2026-08-08](#gui-test-suite-2026-08-08) below: **114 tests
across 9 specs, green on all six distributions**. The 2026-06-29 figure of 113
across five, recorded under
[v1.1.0 Re-validation](#v110-re-validation-2026-06-28), is superseded and is not
comparable: the specs were rewritten in between, so the two numbers count
different tests rather than measuring growth.

**Fedora alone has been re-read since, at 121 on 2026-08-09**, the suite having
grown by the five `T-DIVG-*` tests that #143 added over the rollback modal's
divergence section. That is deliberately not written into the table above: it is
one distribution, and a six-distribution row carrying a one-distribution reading
is the error this document exists to avoid. The other five stand at their
2026-08-08 figures and have not been asked since. The tests added are
distribution-independent, being a mock payload and a computed layout, so there
is no reason to expect them to differ, and no reading says they do not.

### GUI Test Suite, 2026-08-08

| Distribution | Tests run | Passed | Failed | Wall clock |
|--------------|-----------|--------|--------|------------|
| Arch | 114 | 114 | 0 | 1.8 min |
| Debian | 114 | 114 | 0 | 1.7 min |
| Ubuntu | 114 | 114 | 0 | 1.9 min |
| Fedora | 114 | 114 | 0 | 1.8 min |
| Rocky/RHEL | 114 | 114 | 0 | 1.9 min |
| openSUSE Leap 16 | 114 | 114 | 0 | 2.4 min |

Taken at 10:13, after `T-APPLY-01..04` landed. An earlier sweep the same
morning read 110 of 110 across the same six, before those four existed.

The ceiling is 600 s per distribution and nothing is now close to it. It was
binding before this repair, which is what began the investigation: a stale class
in `waitForApp` meant every spec's `beforeEach` waited 30 s, so the setup alone
consumed more than the whole run now takes.

Five faults stood between the previous reading and this one, and only one of
them was about the interface. Recorded here because each failed in a way that
pointed somewhere other than its cause:

- **Ubuntu could not resolve names.** `/etc/resolv.conf` was a symlink to a
  systemd-resolved stub nothing in the container starts, and `--resolv-conf=auto`
  leaves a symlink alone.
- **Rocky installed EPEL over the network and then installed nothing**, in
  silence, every install carrying `2>/dev/null || true` with `-q` hiding the
  successful case.
- **openSUSE asked for package names Leap 16 does not carry**, and zypper
  abandons the whole transaction on one bad name, so Python and Chromium were
  never installed either.
- **openSUSE then had no font.** Its `chromium` pulls none, and a browser with
  no font lays every glyph out at zero width: the markup renders, the icons
  draw, and only assertions on visible text fail, as `hidden`. 72 of 110 failed
  that way against entirely correct markup. `require_a_font` now refuses to
  start the suite, for every distribution rather than this one.
- **Ubuntu's `chromium` is a snap stub**, and the probe tested only that the
  file was executable.

### Test Infrastructure

- **Virtual Display**: none. Xvfb was removed rather than repaired: the config sets `headless: true`, and Fedora's `headless_shell` cannot talk to X at all yet ran the suite, which is the proof that no display was ever wanted. A **font** is required instead, and `require_a_font` refuses to start without one
- **SPA Server**: `gui-tests/spa-server.py` -- Python HTTP server on port 8787 with client-side routing support (all non-file paths return `index.html`)
- **Test Index Generation**: `scripts/test/gui/gui-test-inner.sh` dynamically generates the served `index.html` at test-time by reading `dist/index.html`, stripping SRI `integrity` attributes, and injecting `<script src="/tauri-mock.js"></script>` before the first `<script type="module">` tag
- **Tauri IPC Mock**: `gui-tests/tauri-mock.js` -- JavaScript mock of `window.__TAURI__` injected before WASM loads, covering 31 IPC commands: `run_scan`, `run_scan_filtered`, `run_scan_with_options`, `get_latest_scan`, `run_apply`, `run_apply_dry_run`, `get_checkpoints`, `create_checkpoint`, `delete_checkpoint`, `run_rollback`, `generate_compliance_report`, `export_report`, `export_compliance_report`, `get_scan_history`, `get_scan_session`, `list_plugins`, `get_checkpoint_detail`, `list_remote_hosts`, `save_remote_host`, `delete_remote_host`, `connect_remote`, `disconnect_remote`, `run_remote_scan`, `get_scheduler_config`, `save_scheduler_config`, `test_notification`, `run_fleet_scan`, `run_fleet_apply`, `run_fleet_rollback`, `validate_config`, `pick_config_file`
- **Browser**: System Chromium auto-detected per distribution (no bundled browser)
- **Test Runner**: Playwright (npm) with `gui-tests/playwright.config.js`

### Spec Inventory (9 Specs, 114 Tests)

Counted off `gui-tests/tests/` on 2026-08-08: 84 tests written out, plus 30 the
theme spec generates at collection time (5 states x 6 themes). The 2026-08-07
suite repair rewrote most of these, so the per-spec figures here are a fresh
count and not the 2026-08-01 one they replace.

This matches the six-distribution reading above, which was re-run at 114 once
`T-APPLY-01..04` landed.

| Spec | Test IDs | Tests | Description |
|------|----------|-------|-------------|
| `dashboard.spec.js` | T-DASH-01..09 | 9 | Score display, scan trigger, navigation, activity feed |
| `analysis.spec.js` | T-FIND-01..11, T-COMP-01..08 | 19 | Findings grouping and detail expander, declined exceptions, framework selection, report generation |
| `hardening.spec.js` | T-CONF-01..10, T-HIST-01..06, T-APPLY-01..04 | 20 | Profiles, plugin toggles, preview, cancel; checkpoints, rollback; what an executed apply produces |
| `themes.spec.js` | T-THEME-01..07 | 7 + 30 | 6 of the 7 themes verified, High Contrast not yet covered. The 30 screenshot tests are generated as 5 states x 6 themes |
| `errors.spec.js` | T-ERR-01..04 | 4 | Scan/apply/checkpoint errors, dismiss |
| `fleet.spec.js` | - | 7 | Fleet scan view |
| `fleet-apply.spec.js` | - | 9 | Fleet Apply mode toggle, selection, confirm modal |
| `remote.spec.js` | T-REMOTE-01..03 | 3 | The `/remote` redirect, the saved host list, the Add Host form |
| `scheduler.spec.js` | - | 6 | Scheduler and notification configuration |

### Per-Distro Notes

Recorded on the previous container set. The Chromium package names and paths have
not been re-checked against Debian 13, Fedora 44, Rocky 10 or Leap 16.0.

| Distribution | Chromium Path | Notes |
|--------------|--------------|-------|
| Arch Linux | `/usr/bin/chromium` | Standard package |
| Debian 12 | `/usr/bin/chromium` | Standard package |
| Fedora 41 | `/usr/lib64/chromium-browser/headless_shell` | Uses `chromium-headless` package |
| Rocky Linux 9 | `/usr/bin/chromium-browser` | Requires EPEL + CRB repos, Node.js 20 module |
| openSUSE Leap 16 | `/usr/bin/chromium` | Requires `--gpg-auto-import-keys` for zypper, the `-default` Node metapackages rather than version-suffixed names, and a font package of its own: `chromium` pulls none |

### Running GUI Tests

```bash
# Build the WASM frontend first
cd crates/hardener-ui && trunk build --release && cd ../..

# Run GUI tests across all 5 distributions
sudo ./scripts/test/gui/run-gui-tests.sh

# Or via the cross-distro runner with --gui flag
sudo ./scripts/test/run-cross-distro-tests.sh --gui
```

The first step is not advice. Nothing in the runner invokes `trunk`, so the
containers serve whatever is already in `crates/hardener-ui/dist/`, and a stale
bundle used to fail in the worst available way: the suite ran green against the
previous interface, and a test written for the change failed as though the
change were wrong. `run-gui-tests.sh` now **refuses to start** when anything
under `crates/hardener-ui/src` or `styles.css` is newer than `dist/index.html`,
and names the file that is ahead.

### Output Files

```
test-results/gui/
  arch-webui.log          # Full Playwright output from Arch container
  debian-webui.log        # Full Playwright output from Debian container
  fedora-webui.log        # Full Playwright output from Fedora container
  rhel-webui.log          # Full Playwright output from Rocky 9 container
  opensuse-webui.log      # Full Playwright output from openSUSE container
  screenshots/webui/      # Theme screenshots (30 per distro)
  gui-summary.txt         # Aggregated pass/fail summary
```

---

**Last Updated**: 2026-08-07
