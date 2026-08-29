# Distribution Validation Results

**Last Updated**: 2026-08-27

This document tracks validation testing across supported Linux distributions.

**Last measured full cross-distro validation:** 2026-08-14, on containers
recreated immediately beforehand, by `release-readiness-root.sh` against
`hardener 1.5.1 (6bce4229)`. This line read 2026-08-07 until 2026-08-15 while
the Summary below already recorded the 2026-08-14 run, which is the same defect
shape as a summary contradicting its own table.
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

> **What is historical here.** The 2026-08-14 summary immediately below is the
> current reading. This callout said 2026-08-07 until 2026-08-17, after the
> opening line above had already been corrected to 2026-08-14: one copy moved and
> this one did not, which is the defect this document keeps recording. Everything under [v1.1.0 Re-validation](#v110-re-validation-2026-06-28)
> and every per-distro breakdown after it is a dated record kept for its failure
> analysis and its per-plugin detail, not a statement about the containers as they
> stand today.

---

## Summary

Measured 2026-08-14 by `scripts/test/run-cross-distro-tests.sh --apply
--booted`, with all six containers recreated and their contract verified first.

**The binary that produced this reading**, captured by
`release-readiness-root.sh` into
`test-results/release-readiness/00-preflight.log` before any container was
touched:

    Binary version: hardener 1.5.1 (6bce4229 2026-08-14)
    Tree version:   1.5.1
    Tree commit:    6bce4229
    Tree status:    0 modified path(s)

That line is here because a reading without it cannot be attributed. A stale
musl binary in a container has produced a green matrix before, and every
failure in such a run is charged to code the binary does not contain. The
pre-flight refuses a mismatch outright rather than warning: on the run above it
first aborted on `binary built at 69ed307d, HEAD is 6bce4229`, and the reading
was taken only after a rebuild.

The wider release sweep, which recreates all six containers before every suite
that uses one, is:

```bash
sudo ./scripts/test/release-readiness-root.sh
```

| Distribution | Family | Version | Test Date | Declared | Recorded | Pass | Fail | Skip | Status |
|--------------|--------|---------|-----------|----------|----------|------|------|------|--------|
| Arch Linux | Arch | Rolling | 2026-08-18 | 149 | 149 | 147 | 0 | 8 | VALIDATED |
| Debian | Debian | 13 (Trixie) | 2026-08-18 | 149 | 149 | 147 | 0 | 8 | VALIDATED |
| Ubuntu | Debian | 24.04 LTS (Noble) | 2026-08-18 | 149 | 149 | 147 | 0 | 8 | VALIDATED |
| Fedora | Red Hat | 44 | 2026-08-18 | 149 | 149 | 147 | 0 | 8 | VALIDATED |
| Rocky Linux | Red Hat | 10 | 2026-08-18 | 149 | 149 | 147 | 0 | 8 | VALIDATED |
| openSUSE | SUSE | Leap 16.0 | 2026-08-18 | 149 | 149 | 147 | 0 | 8 | VALIDATED |

**Re-measured 2026-08-18 against `hardener 1.5.1 (653b4ff1)`**, all six
containers destroyed and recreated first, through
`sudo ./scripts/test/release-readiness-root.sh`. Every column is identical to
the 2026-08-14 reading, which is the result that was wanted: nothing between the
two commits touched a plugin, and a moved figure would have said otherwise. The
same run recorded **differential** at arch 96 of 96 with 10 unaskable and the
other five 98 of 98 with 8, **package** at 28 of 30 with 2 skipped on all six,
and **polkit** with its three interactive tests skipped. The unbooted rollback
arm exits 2 ("passed, but 2 checks were not asked") because
`release-readiness-root.sh` runs it under `--pipe`, so `systemctl mask` and
`systemctl start` have no service manager; the booted arm measured those two
plus audit.

The pass count rose by one and the skip count fell by one against the
2026-08-07 reading, and no check was added or removed to do it: section 23's
`ssh-hardening` checkpoint row was recorded and then skipped, and now carries a
verdict. Why that mattered is under
[Expected Container Skips](#expected-container-skips-8-per-distro).

The differential suite ran the same day on the same six: arch 86 of 86 with 10
unaskable, and the other five 88 of 88 with 8 unaskable. Arch differs because two
further rows are unaskable there, not because anything failed.

It has grown since and was re-run booted on 2026-08-11 against `d04de4c4`, with
all six containers recreated first: **arch 96 of 96 with 10 unaskable, and the
other five 98 of 98 with 8 unaskable, no failures and no skips anywhere.** The
gap between the two readings is the suite gaining checks, not a distribution
changing: the arch difference is the same two rows in both.

Re-run booted again the same day against `dd85255f`, the v1.6.0 release
candidate, containers recreated first. **Every count is identical to the
`d04de4c4` reading**, which is the result that was wanted: two changes in that
range would have shown here if anywhere, `fb98c044` altering checkpoint capture
for special files and `dabbb1fe` pinning the remote metadata probe to `LC_ALL=C`,
and neither moved a row. Declared plus unaskable is 106 on all six in both
readings, so no row went missing rather than passing.

The Playwright GUI suite was read the same day, also against `7c81c491` and on
the same six: **134 of 134 everywhere, none failed, none skipped, none flaky**,
one worker and no name filter. It read 127 earlier the same day, and the seven
added between the two readings are `T-THEME-08`, `T-THEME-09` and the five High
Contrast screenshots. Every theme the application offers is now covered,
and `T-THEME-09` compares the selector's own option list against the suite's,
so the next theme added cannot arrive uncovered.

Re-read against `dd85255f` on 2026-08-12, after a `trunk build --release`:
**134 of 134 on all six, none failed, none skipped, no name filter.** rhel took
two runs. The first never started a test: `dnf` could not fetch `baseos` and
`appstream` metadata, so chromium, node and the fonts never installed, and the
runner refused to continue with no font under `/usr/share/fonts` rather than let
Chromium lay every glyph out at zero width. The mirrors answered 200 from the
host at the time, DNS resolved inside the container under the runner's own nspawn
flags, and `dnf makecache` returned 0 on the next attempt, so the cause was a
transient mirror failure and **nothing in the repository was changed for it**.
The on-disk `/etc/resolv.conf` differs per container, 22 bytes naming
`100.64.0.7` on rhel against fedora's 920-byte stub, and that is a red herring:
nspawn overrides the file at runtime and both see `127.0.0.53`, which works
because no `--private-network` means the container shares the host's loopback.

**Both 134-of-134 readings above are superseded, and the 142 static count that
replaced them never was a result.** That figure came from `npx playwright test
--list` against the working tree and had been read on no container.

**Measured 2026-08-15 against `hardener 1.5.1 (4284612d)`, all six containers
recreated first: 152 of 152 on every distribution, none failed, none skipped,
none flaky, 37 screenshots each.**

**Superseded 2026-08-16 against `hardener 1.5.1 (5b715039)`, all six containers
recreated first: 154 of 154 on every distribution, none failed, none skipped,
none flaky, 3.3 to 3.8 minutes each.** The suite grew by two, `T-DASH-10` and
`T-FIND-12`, which assert the Dashboard and Analysis header subtitles. Their
subject is the reason this reading was taken rather than inherited: the
populated branch of `last_scanned_label` had never rendered in any test or any
of the 222 screenshots, because the Playwright fixture claimed a completed scan
while omitting its completion time, and both pages therefore printed "Not
scanned yet" over a score of 60/100. **That is a defect no count in this
document could have caught**, found by reading the captures rather than the
results, and the captures at `5b715039` show the subtitle populated.

That run is also the first in which `tests/contrast.spec.js` measured anything
at all. It landed on 2026-08-13, after every reading above, and its rule
flattener dropped every style rule it was given, so it collected 0 pairings and
its own vacuity guard failed all seven theme cases (#173, fixed in `05510893`).
The first repaired run then failed 1 of 152 on a real defect, four Daywatch
pairings below the WCAG bar, fixed in `4284612d`. **A green suite is not
evidence of contrast, and for two days this one was green about nothing.**

Two suites in the **2026-08-07** release-readiness run did not pass, and neither
reading is about a distribution. That run is named explicitly because the
paragraphs above it now describe later ones, and "that run" had come to point at
the 2026-08-16 reading, which passed 154 of 154.
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

> **Why passed plus failed does not reach the recorded total.** Two of the 149
> recorded checks are section 23 rows that are recorded and then skipped: the ssh
> plugin's apply has nothing to do on a host sections 13 to 15 have already
> hardened, so it takes no checkpoint, and with no checkpoint of its own there is
> nothing to roll back and nothing to read afterwards. That outcome is declared,
> not a fault. The row that establishes it is a pass rather than a third skip,
> because the apply's own change list is read to confirm it changed nothing: an
> apply that changed the host and recorded no checkpoint reaches the same branch,
> and what it did could not be rolled back at all. The other six of the eight
> skips are never recorded as checks at all. The full breakdown is under
> [Expected Container Skips](#expected-container-skips-8-per-distro).

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
> - **Debian** covers Linux Mint, Pop!\_OS and elementary OS. **Ubuntu is no
>   longer covered by proxy**: it joined `DISTRO_ORDER` on 2026-08-07 and has its
>   own container and its own dated readings
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
booted container under `--apply` the suite **declares 159 checks** per
distribution, having declared 149 until 2026-08-19, 151 for part of that same
day, and 157 until 2026-08-21. Section 12A gained two: it creates
`/etc/audit/audit.rules.prev` itself where an apply leaves none, and asserts its
presence before the rollback and its absence after. The `FRAMEWORKS` table then
gained the three frameworks it had never named, which is six more checks, three
in section 5 and three in section 7. Section 5A then added the last two, the
profile label in a report heading, and every measurement recorded below predates
it.

**Measured at 157 declared, 155 passed, 0 failed, 8 skipped on all six**, at
`5652bb45` on 2026-08-19, every container recreated immediately beforehand.
Each log records `Version: hardener 1.5.1 (5652bb45 2026-08-19)`, so the reading
is of this tree and not of a binary an earlier run left behind. All six added
checks passed on all six distributions, `Report --framework` and `PDF:` for
`soc2`, `800-171` and `fedramp`, and each container ended with ten framework
PDFs on disk between 27 and 35 KB. The skip arithmetic is unmoved from the
reading below: 8, of which 2 are declared without a verdict and 6 are never
declared.

The reading below is the one that stood before those six checks existed. It is
kept because it is what the paragraphs after it are about.

**Measured at 151 declared, 149 passed, 0 failed on all six.** arch, debian,
ubuntu and fedora and RHEL at `99723784`; openSUSE at `c269ef84`, run on its own
after the fix below. On every one of the six `augenrules` wrote the backup
during the apply and the rollback removed it, so the fallback that creates one
never fired and the removal path was exercised by the real mechanism rather than
by a stand-in.

openSUSE reached that only on the second attempt. It recorded 143 at
`99723784`, because its audit package **ships** `/etc/audit/audit.rules.prev`
and the first version of the check refused that as run residue rather than the
pristine state it is, failing and returning before the other eight checks in the
section. The check now removes the file before taking its baseline, so every
distribution asks the same question; its log carries `This image ships
/etc/audit/audit.rules.prev` on that host and on no other.

That also corrects a measurement recorded in `audit_mock_tests.rs`, which had
openSUSE producing no `.prev` at all. It produces one like everywhere else; the
shipped copy meant there was never a new one to notice. The tables below record
149 because that is what those earlier runs recorded.

### Running the Tests

```bash
# Build the musl static binary first. No copy afterwards: the runner resolves
# the target directory itself through `resolve_target_dir` and prefers the musl
# artefact, and this machine's cargo config puts `target/` outside the tree, so
# a `cp target/...` here copied from a path that does not exist.
cargo build --release --target x86_64-unknown-linux-musl -p hardener-cli

# Recreate the containers. Sections 12A and 12B ask whether a rollback REMOVES
# something an apply created, which can only be asked of a host where it does
# not exist yet, and --apply hardens every container it touches. The list is
# `DISTRO_ORDER` in `scripts/lib/common.sh`; it omitted `ubuntu` here until
# 2026-08-19, and a loop short one distribution recreates five and leaves the
# sixth to run --apply against the previous run's leftovers.
for d in arch debian ubuntu fedora rhel opensuse; do
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

### Expected Container Skips (8 per distro)

On an `--apply --booted` run every distribution skips exactly 8, and the same 8:

| # | Section | Test | Reason |
|---|---------|------|--------|
| 1 | 10 | Daemon start | Blocking command that would hang the test runner |
| 2 | 12 | Systemd install | No full systemd init (PID 1) in nspawn |
| 3 | 12 | Systemd status after install | Depends on systemd install |
| 4 | 12 | Systemd uninstall | Depends on systemd install |
| 5 | 14 | Apply audit-hardening | No kernel audit subsystem available in container |
| 6 | 14 | Apply mac-hardening | No SELinux/AppArmor kernel modules in container |
| 7 | 23 | Lifecycle rollback: ssh-hardening | ssh recorded no checkpoint of its own, so there is none to roll back |
| 8 | 23 | Lifecycle: ssh-hardening findings after the rollback | Follows from 7: nothing was rolled back, so nothing to read |

The row above those two, `Lifecycle: ssh-hardening's apply recorded a checkpoint
for whatever it changed`, was a third skip until 2026-08-14 and is now a pass.
It had reported "it took no checkpoint, so it had nothing to do", which is the
usual reason and was never the thing measured: an apply that changed this host
and recorded no checkpoint reaches the identical branch, and nothing it did
could be rolled back. `apply_real_change_count` reads the apply's own change
list, counting every `change_type` except `Skipped` and `Checkpoint`, so the
row now passes on a confirmed no-op and fails on an unrollbackable write.
Measured on all six: ssh reports no real change there, so the outcome the skip
had assumed is now the outcome it asserts.

Skips 1 to 6 are never recorded as checks. Skips 7 and 8 are recorded and then
skipped, which is why 147 passed and 0 failed out of 149 recorded rather than
149 passed. The runner now prints that split rather than leaving it to be
worked out: a clean run reads `149 declared, 147 passed, 0 failed, 8 skipped (2
declared without a verdict, 6 never declared)`, so the row adds up on the page.
It used to read `146/149 passed, 9 skipped` with no failure count at all, which
was read as three silent failures on a run that had none. The first number in
the bracket is derived as declared minus resolved, so it says what it measures
rather than what it is usually taken to mean: on a clean run those are the
skips taken after the check was announced, and a check that fell out of its
section without any verdict at all would land there too.

The figures in that sample are the ones runs up to 2026-08-19 recorded. Section
12A then gained two checks, and a clean run read `151 declared, 149
passed, 0 failed, 8 skipped (2 declared without a verdict, 6 never declared)`.
The skip arithmetic is unaffected, neither new check being skippable. Measured
in that shape on arch, debian, ubuntu, fedora and RHEL at `99723784`. The
framework table then gained six more, and a clean run now reads `157 declared,
155 passed, 0 failed, 8 skipped (2 declared without a verdict, 6 never
declared)`. **Measured in that shape on all six at `5652bb45`**, containers
recreated first, which is the reading that turned the sentence this replaces
from a derivation into a measurement.

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
| 5 | Reports, All 10 Frameworks | 10 | cis, stig, nist, pci-dss, hipaa, gdpr, iso27001, soc2, 800-171, fedramp. The last three joined on 2026-08-19 and no matrix run has rendered them yet |
| 5A | Report Profile Labels | 2 | The STIG and CIS headings name the identifier scheme this host is scored against, read off stdout. Section 5 above checks only the exit status, which a host scored against the wrong catalogue also returns. Two arms: the `rhel` container is Rocky Linux 10 and must carry `(DISA RHEL 10 STIG V1R1)` and `(CIS RHEL 10 Benchmark v1.0.1)`; the other five must carry `(RHEL 8 baseline IDs)` and an unlabelled CIS heading. Both arms are asserted, so a resolution that collapsed to one profile everywhere fails somewhere whichever way it collapsed. Two checks on every distribution, so the declared size does not vary with the container. Added 2026-08-21 and not yet met by a container |
| 6 | Reports All Scenarios | 7 | server, workstation, government, healthcare, financial, gdpr, all |
| 7 | Report Output Formats | 15 | text, json, csv, html and pdf for CIS, plus a PDF for each of the 10 frameworks |
| 8 | Dry-Run All Plugins | 9 | --dry-run for all 8 plugins, plus --all |
| 9 | Checkpoint Operations | 5 | list, create, list again, show, delete |
| 10 | Daemon Commands | 2 | status, run-once (daemon start is skipped) |
| 11 | History Commands | 5 | list, show, export, trends, regressions |
| 12 | Systemd Commands | 2 | generate, status (install/status/uninstall skipped in a container) |
| 12A | Rollback Undoes The Audit Apply | 9 | Apply audit hardening, roll it back, and assert on the filesystem that the rules file is gone, that `/etc/audit` lists exactly the paths it listed beforehand, and that the compiled rule set is back at its pre-apply line count. Two of the nine are the backup rows added on 2026-08-19: `/etc/audit/audit.rules.prev` present before the rollback and absent after (--apply only) |
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
```

The musl binary is ~13MB and works across all glibc versions. **No copy into
`target/release/` is needed**, and the `cp` that stood here until 2026-08-19
failed on any machine whose cargo config puts the target directory outside the
tree: the runner resolves it through `resolve_target_dir` and prefers the musl
artefact of its own accord.

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
   - `sudo ./scripts/containers/create-container.sh ubuntu` (Ubuntu 24.04 LTS Noble via debootstrap)
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
   ```
   No copy afterwards; see Build Notes.

3. **Run the cross-distro test suite**:
   ```bash
   sudo ./scripts/test/run-cross-distro-tests.sh --apply --booted
   ```

4. **Review results** -- The runner writes `test-results/summary.txt` and a per-distro `test-results/<distro>.log`, and prints the same table to stdout.

---

## GUI Testing (Web UI -- Playwright)

In addition to CLI testing, the Web UI is validated with Playwright across all
six distributions.

> **The current reading is not in this section.** It is the 2026-08-21 run:
> **165 of 165 on every distribution**, none failed, none skipped, none flaky,
> 3.7 to 4.7 minutes each, 44 screenshots each, one worker and no name filter.
> **The containers were not recreated for it.** All six were created on
> 2026-08-19 between 21:53 and 22:00 and have been reused since, read from
> their directory birth times; `run-gui-tests.sh` permits this because it only
> checks that a container exists and skips when one does not, recreation being
> a separate manual step.
>
> **The two contrast routes that first open a modal landed the same day**, with
> `rollback_mode=partial`, the fixture flag they turned out to need. Every
> prediction `04930f71` made is now measured rather than computed:
> `.restore-error` 5.91 to 13.68 against a predicted 5.91 to 13.68,
> `.restore-warn .restore-error` 5.55 to 15.02 against 5.55 to 15.02, and
> `.exception-modal .modal-error` 5.02 to 8.33 against 5.00 to 8.32. Arch and
> openSUSE agree to the digit on all five dark-theme readings.
>
> **The first run of those routes was GREEN while measuring the wrong thing.**
> It collected fourteen `.restore-error` pairings and `--color-critical-bright`
> was in none of them, both default instances being overridden by a more
> specific rule; the rule's own colour renders only when a file or reload fails,
> which the all-success fixture never produced. `MUST_REACH` asks whether a
> selector was measured, not which rule won the cascade for it, so it could not
> have caught this. Detail in `docs/reference/what-is-not-proven.md`.
>
> **The suite grew by seven without a single new `test()` call site**, which is
> the one shape `validate_cross_document_facts.py` documents itself as unable
> to see. The theme sweep gained a sixth state, so seven cases appeared inside
> a site that already existed, and the call-site count stayed at 117 while the
> case count moved 158 to 165. The validator was green throughout, against
> documents that all said 158. It is registered against the row below marked
> **current**, so that row is what turns them red, and nothing in the tree
> could have turned the row itself red.
>
> **A six-distribution run earlier the same day was not green**, and it is
> kept in the Reading table rather than dropped: 157 of 157 on five and one
> failure on openSUSE, which was not an openSUSE fault but a race the other
> five won. Everything below is either
> infrastructure read off the tree or a dated record kept for its failure
> analysis.
>
> **The 156 was a declaration for one day and is now a result.** `T-FLEET-10`
> and `T-SCHED-07` were written on 2026-08-18 and could not be run when they
> were written, so every site carrying the figure said which kind of number it
> was until this run. Both executed and both passed on all six. The distinction
> is kept in this paragraph rather than deleted, because it is the one a reader
> needs the next time a case is added between runs.
>
> This block previously claimed the last run was 2026-06-29 and that the suite
> had not been re-run since the desktop redesign. Both were true when written
> and neither is now, which is the hazard of a second place to record one fact:
> the Summary was corrected and this copy was not.

### Summary

| Distribution | Family | Version | Test Date | Tests | Pass | Fail | Status |
|--------------|--------|---------|-----------|-------|------|------|--------|
| Arch Linux | Arch | Rolling | 2026-02-23 | 84 | 84 | 0 | VALIDATED (v0.3.3 baseline) |
| Debian | Debian | 12 (Bookworm) | 2026-02-23 | 84 | 84 | 0 | VALIDATED (v0.3.3 baseline) |
| Fedora | Red Hat | 41 | 2026-02-23 | 84 | 84 | 0 | VALIDATED (v0.3.3 baseline) |
| Rocky Linux | Red Hat | 9 | 2026-02-23 | 84 | 84 | 0 | VALIDATED (v0.3.3 baseline) |
| openSUSE | SUSE | Leap 15.6 | 2026-02-23 | 84 | 84 | 0 | VALIDATED (v0.3.3 baseline) |

The suite has grown since that baseline, and has since been rewritten. Every
figure in the table above is superseded by the reading in the Reading table
below, which is **175 of 175 on all six distributions** on 2026-08-29.
Restating the number here rather than only pointing at it is deliberate, and so
is holding it to the collection count: a pointer that cannot go stale is a
pointer nothing checks.

This site and the current Reading row have now stood red twice in one day, at
166 against a tree of 168 and then at 168 against a tree of 171, each time for
the hours between the specs being written and the sweep that ran them. **Neither
number was edited while it stood**, and both times the run cleared it, which is
the only thing that can.

This sentence named the 2026-08-16 reading of 154 until 2026-08-19. Summary had
recorded the later reading on 2026-08-18, so the pointer stood stale for a day:
the number it carried was a correct reading and the **pointer** to it was what
went stale, which is the harder half of this class to see. **It happened again
immediately**: the 2026-08-19 fix moved the number 154 to 156 and carried the
`[Summary](#summary)` link over untouched, so from 2026-08-20 the sentence
named 156 while the suite read 157, and the link itself was ambiguous, two
headings in this file being named Summary. It resolved to the CLI one at the
top, whose GUI figure is 134. **The link is now gone rather than repointed**,
because the table it means sits directly below the sentence. None of the
intermediate figures is comparable to it or to each other, because the specs
were rewritten between several of them, so the numbers count different tests
rather than measuring growth:

| Reading | Tests | Distributions | Standing |
|---------|-------|---------------|----------|
| 2026-02-23 | 84 | 5 | v0.3.3 baseline, table above |
| 2026-06-29 | 113 | 5 | superseded, specs rewritten after it |
| 2026-08-08 | 114 | 6 | superseded, [below](#gui-test-suite-2026-08-08) |
| 2026-08-09 | 121 | Fedora only | superseded, never a six-distribution reading |
| 2026-08-11 | 134 | 6 | superseded, against `7c81c491` |
| 2026-08-12 | 134 | 6 | superseded, against `dd85255f` after a `trunk build --release` |
| 2026-08-15 | 152 | 6 | superseded |
| 2026-08-16 | 154 | 6 | superseded, against `5b715039` |
| 2026-08-18 | 156 | 6 | superseded, against `653b4ff1` |
| 2026-08-20 | 157 | 6 | superseded, against `2bc8bd76` |
| 2026-08-21 | 157 | 6 | **not green**: 5 distributions passed, openSUSE failed T-SCHED-07. Not an openSUSE fault - a load racing an edit, which the other five happened to win |
| 2026-08-21 | 158 | 6 | superseded, taken twice at this count: once after the fix for that race and the test that pins it, and again after the fleet-apply fixture gained a failing host, which the nine `T-FAPPLY` cases read |
| 2026-08-21 | 165 | 6 | superseded, 3.7 to 4.7 minutes each and 44 screenshots each. The theme sweep gained a sixth state, the rollback modal, so the whole modal surface is now captured in all seven themes instead of in one as a by-product of `T-DIVG-03`'s geometry check. **Seven cases from no new call site**: the count below stayed at 117 and every document said 158 with the validator green |
| 2026-08-21 | 165 | 6 | superseded, against the two contrast routes that first open a MODAL and the `rollback_mode=partial` fixture they needed. Five distributions green in one sweep; openSUSE failed `T-FIND-10` on a 30 s `waitForApp` timeout and passed on a re-run at 165. **Kept rather than dropped, and it was NOT a distribution fault**: the identical `beforeEach` succeeded 24 times in that same file, run and container, with `T-FIND-09` and `T-FIND-11` passing either side of it in 2.6 s and 1.7 s. A real fault in a shared hook fails all 25. openSUSE took 5.6 minutes here against 4.7 in the sweep before, so it is load |
| 2026-08-22 | 166 | 6 | superseded. The first execution of `T-FLEET-11`, authored unexecuted alongside the fleet profile badge; all six green in one sweep with no re-run |
| 2026-08-27 | 168 | 6 | superseded, against `b3caf49f`, the first execution of `T-HIST-14` and `T-HIST-15`. 44 screenshots each. **Debian needed one re-run**: `T-HIST-15` timed out in the shared `beforeEach` at 30 s waiting for `getByRole('main')`, with the page still on the WASM `Loading...` splash, so its own assertions never ran. The other five passed that spec, and the other twelve History specs passed on Debian through the identical hook, which is what says cold-start timing rather than a defect. Re-run alone: 168 of 168 |
| 2026-08-27 | 171 | 6 | superseded, the first execution of `T-CONF-11`, `T-CONF-12` and `T-CONF-13`. All six green in one sweep with no re-run, 4.5 to 6.5 minutes each and 44 screenshots each. **Every log reports `624ce1a7` while the tree was at `25700268`**, and that is right rather than stale: the bundle is compiled from the working tree and stamps the last commit that existed when `trunk build` ran, which here was before the commit the same tree became. The `hardener-ui`, `styles.css` and `hardener-types` edits under test were all in the bundle; the only thing that changed after the build was documentation. Read the stamp as "which sources", not "which commit". The three new cases are what make the picker's warning observable at all: inverting the condition that decides it compiles and left every Rust test green |
| **2026-08-29** | **175** | **6** | **current**, against `6126bb42`. The first execution of `T-FIND-13`, `T-FIND-14`, `T-CONF-14` and `T-CONF-15`, all four authored the same day for two defects the suite could not previously see. All six green in one sweep with no re-run, 4.2 to 5.3 minutes each, every log stamping `6126bb42`. **The two T-FIND cases assert a notice the theme sweep had been screenshotting happily while it did not exist**, which is the difference between capturing a view and checking it. The two T-CONF cases need `?preview_mode=blocked`, a fixture added with them: the default stages changes, so the zero-change summary was unreachable and went unasserted while telling an operator with nine findings that the host was already compliant |

The Fedora-only row is kept because it records a rule rather than a result: it
was deliberately never written into the table, since a six-distribution row
carrying a one-distribution reading is the error this document exists to avoid.
The 2026-08-16 run asked all six and settled it.

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
- **Tauri IPC Mock**: `gui-tests/tauri-mock.js` -- JavaScript mock of `window.__TAURI__` injected before WASM loads, covering 34 IPC commands: `add_policy_exception`, `connect_remote`, `create_checkpoint`, `delete_checkpoint`, `delete_remote_host`, `disconnect_remote`, `export_compliance_report`, `export_report`, `generate_compliance_report`, `get_checkpoint_detail`, `get_checkpoints`, `get_host_history`, `get_latest_scan`, `get_scan_history`, `get_scan_session`, `get_scheduler_config`, `list_plugins`, `list_remote_hosts`, `pick_config_file`, `remove_policy_exception`, `run_apply`, `run_apply_dry_run`, `run_fleet_apply`, `run_fleet_rollback`, `run_fleet_scan`, `run_remote_scan`, `run_rollback`, `run_scan`, `run_scan_filtered`, `run_scan_with_options`, `save_remote_host`, `save_scheduler_config`, `test_notification`, `validate_config`. Counted off the mock's `case` labels, not maintained by hand; the two that were missing from this list until 2026-08-16, `add_policy_exception` and `remove_policy_exception`, had been in the mock since the exception controls landed. **This set is not `src-tauri/build.rs`'s `COMMANDS`, and should not be read as it:** the mock answers what the frontend calls, so it carries `run_scan_filtered`, `run_scan_with_options` and `export_report`, which are not registered commands, and omits `run_deep_scan`. Registered set: 32, mock set: 34, overlap 31. `get_host_history` was the second omission until 2026-08-18 and was the asymmetric one: `run_deep_scan` sits behind a button no spec clicks and both its call sites `match` on the result, while `get_host_history` fires on every fleet row expand and its rejection was swallowed. That asymmetry, and what is still owed on the one now answered, is analysed in [what-is-not-proven.md](what-is-not-proven.md#does-any-of-this-cover-the-desktop-application) rather than restated here
- **Browser**: System Chromium auto-detected per distribution (no bundled browser)
- **Test Runner**: Playwright (npm) with `gui-tests/playwright.config.js`

### Spec Inventory (11 Specs, 175 Tests)

Counted off `npx playwright test --list` on 2026-08-21, and confirmed by the
second 2026-08-27 sweep, which executed all 171. The three added that day,
`T-CONF-11`, `T-CONF-12` and `T-CONF-13`, cover the config picker's two-rule
warning, its absence for a trusted path, and the dialog failure that used to
reach only the browser console.
**127 `test()` call sites produce 175 cases**, because three sites are
parameterised and
generate their cases at collection time: `themes.spec.js:200` produces 42
screenshots (6 states x 7 themes), `contrast.spec.js:765` produces one case per
theme, and `hardening.spec.js:614` produces one per viewport width. Reading the
runner rather than grepping the sources is therefore deliberate: a count of
`test(` calls is 127 and understates the suite by 48.

This is a **collection** count, and the sweep of 2026-08-22 has now executed
all of it: `T-FLEET-11` was added with the fleet profile badge, stood unexecuted
for a day, and ran green on all six distributions in the current row of the
Reading table above. While it stood unexecuted the two numbers differed and
three registered sites read 165 against a tree of 166. **That red was correct
and was left standing rather than edited away**, because a Reading row records
what a run did and not what the tree holds; the only thing that could clear it
was a run.

**All three line numbers were stale when this paragraph was rewritten**, and
only one of them by the change that prompted the rewrite. The sweep genuinely
moved from 152 to 200, but `contrast.spec.js` was named at 364 while its site
sat at 551 and `hardening.spec.js` at 470 while its site sat at 464, both
displaced by edits elsewhere in their own files that never touched the sites.
A line number is the one kind of cross-reference that goes wrong without anyone
editing the thing it names, and nothing checks these three.

| Spec | Test IDs | Tests | Description |
|------|----------|-------|-------------|
| `themes.spec.js` | T-THEME-01..09 | 9 + 42 | All seven themes verified. The 42 screenshot tests are generated as 6 states x 7 themes. The sixth state is the rollback modal, added 2026-08-21 so that `.modal` is captured in every theme rather than in one: it had been shot only as a by-product of `T-DIVG-03`'s geometry check, which parameterises over viewport width and not over theme, so sentinel - where `.restore-error` read 3.25 before `04930f71` - had no modal shot at any width. Each state applies its own theme rather than the loop applying one afterwards, because `.modal-backdrop` covers the theme selector once a modal is open |
| `hardening.spec.js` | T-CONF-01..13, T-HIST-01..06 and 11..15, T-APPLY-01..04, T-DIVG-01..05 | 34 | Profiles, plugin toggles, preview, cancel; checkpoints, rollback, signature verification, unread sources, another host's checkpoints and an unreadable detail; the config picker's apply-tier warning and its dialog failure; what an executed apply produces; the rollback modal's divergence section. T-DIVG-03 runs once per viewport width, so this spec has 33 ids over 34 tests, and T-HIST-07..10 do not exist. This row read 29 with ids to T-HIST-13 while the file held 31, because adding a test moves a total the validator checks and a per-spec row it does not |
| `analysis.spec.js` | T-FIND-01..12, T-COMP-01..08, T-EXC-01..05 | 25 | Findings grouping and detail expander, framework selection, report generation, the per-finding accept/remove exception controls |
| `dashboard.spec.js` | T-DASH-01..11 | 11 | Score display, scan trigger, navigation, activity feed, the header subtitle's scanned state, and T-DASH-11 asserting that only a framework carrying exclusions gets the excluded annotation |
| `fleet.spec.js` | T-FLEET-01..11 | 11 | Fleet scan view, per-host results, row expander, delete confirmation, the expanded host's persisted history rail |
| `fleet-apply.spec.js` | T-FAPPLY-01..09 | 9 | Fleet Apply mode toggle, selection, confirm modal |
| `settings.spec.js` | T-SET-01..08 | 8 | Settings page |
| `contrast.spec.js` | T-CONTRAST | 7 | One case per theme over the computed cascade (#158). Carries two vacuity guards, because a sweep that collects nothing would otherwise pass: a floor on pairings measured, and since 2026-08-20 a separate one on partly-translucent fills, which the colour-only rules would otherwise clear on their behalf. **13 routes**, 11 of which need a state the default fixture does not produce: a scan, an apply under `apply_mode=mixed`, a failed export under `error_mode=export`, a fleet scan with the failing host expanded and the same host left open across a scan that fails it, three states of the fleet apply page, and a scan held mid-flight. The count in this cell said five until 2026-08-21, having gone stale twice while routes were added, and is registered in `validate_cross_document_facts.py` as of 2026-08-21 so that it cannot go stale a third time; the routes themselves are guarded by `MUST_REACH`. Several exist solely to render one rule: `.partial-row-badge-failed` and `.status-error` are the only rules in the stylesheet putting real text over a translucent fill, `.severity_low` is text on exactly one of its two call sites, and the fleet apply pair was added because `.host-row-error` has a second caller on a page nothing had ever loaded. Two of them, added 2026-08-21, are the first that open a MODAL: no route ever had, which is why `.restore-error` and `.exception-modal .modal-error` could fail WCAG permanently in five themes each with both checks silent. They are the only routes carrying a `scope`, confining the sweep to `.modal`, because `.modal-backdrop` is an overlay rather than an ancestor and the page behind an open dialog would otherwise be measured as though undimmed - a false pass, since compositing rgba(0, 0, 0, .5) over text and fill alike makes the rendered contrast worse than the computed number |
| `scheduler.spec.js` | T-SCHED-01..08 | 8 | Scheduler and notification configuration, the two notes that appear only while scheduled scanning is off, and that nothing on the page is editable before the config it is made of has arrived |
| `errors.spec.js` | T-ERR-01..04 | 4 | Scan/apply/checkpoint errors, dismiss |
| `remote.spec.js` | T-REMOTE-01..03 | 3 | The `/remote` redirect, the saved host list, the Add Host form |

### Per-Distro Notes

Recorded on the previous container set. The Chromium package names and paths have
not been re-checked against Debian 13, Fedora 44, Rocky 10 or Leap 16.0, and
**Ubuntu has never been recorded here at all**: it joined `DISTRO_ORDER` on
2026-08-07, after this table was taken, and the GUI suite has run green on it
since without its Chromium path ever being written down. Nothing reads this
table: `gui-test-inner.sh:225` walks a candidate list and takes the first usable
binary, falling back to Playwright's own download, which is why six
distributions pass against a five-row table.

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

**Last Updated**: 2026-08-27
