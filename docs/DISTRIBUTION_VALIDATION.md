# Distribution Validation Results

This document tracks validation testing across supported Linux distributions.

**Last full cross-distro validation:** hardener **1.1.0** (CLI suite, 2026-06-28 — see [v1.1.0 Re-validation](#v110-re-validation-2026-06-28))
**Baseline validation:** hardener 0.3.3 (2026-02-23 — detailed per-distro sections below remain the reference breakdown)
**Container set:** unchanged since baseline (Arch rolling, Debian 12, Fedora 41, Rocky 9, openSUSE Leap 15.6); distro-version refresh still pending

> **Currency note (2026-06-28):** the v1.1.0 binary has now been re-validated
> across all five containers (see [v1.1.0 Re-validation](#v110-re-validation-2026-06-28)).
> However, the **container distro versions are unchanged** from the baseline run —
> newer stable releases (**Debian 13 "Trixie", Ubuntu 26.04 LTS, Fedora 44,
> RHEL 10, openSUSE Leap 16**) have **not** yet been validated, as that requires
> recreating the containers. Family-based detection still routes them correctly.
> **openSUSE Leap 15.x reached end-of-life in April 2026** — re-pin the SUSE
> container target to Leap 16 when refreshing. The version refresh remains a P3
> task in `NEXT.md`.

---

## Summary

| Distribution | Family | Version | Test Date | Tests | Pass | Fail | Skip | Pass Rate | Status |
|--------------|--------|---------|-----------|-------|------|------|------|-----------|--------|
| Arch Linux | Arch | Rolling | 2026-06-28 | 127 | 127 | 0 | 6 | 100% | VALIDATED |
| Debian | Debian | 12 (Bookworm) | 2026-06-28 | 127 | 127 | 0 | 6 | 100% | VALIDATED |
| Fedora | Red Hat | 41 | 2026-06-28 | 127 | 127 | 0 | 6 | 100% | VALIDATED |
| Rocky Linux | Red Hat | 9 | 2026-06-28 | 127 | 127 | 0 | 6 | 100% | VALIDATED |
| openSUSE | SUSE | Leap 15.6 | 2026-06-28 | 127 | 127 | 0 | 6 | 100% | VALIDATED |

> **v1.1.0 (2026-06-28), clean run — 127/127 on all five.** The suite grew from
> 123 to 127 tests: ISO/IEC 27001:2022 added as the 7th report framework, plus
> `history trends`/`history regressions` cases. Two harness issues found and fixed during
> re-validation — stale `daemon status` invocations and an intermittent JSON-grep
> flake — are written up under [v1.1.0 Re-validation](#v110-re-validation-2026-06-28).
> No product regressions. The musl static binary works across all glibc versions.

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

The container image (`packaging/docker/Dockerfile` — `rust:1.97-alpine` build
stage, `FROM scratch` runtime carrying only the static musl binary) was built
from a clean tree and validated on the Arch host (Docker 29.6.1). The image
supports **scan and report only**; `apply` is unsupported in-container by
design and was deliberately not validated. Usage and the capability boundary:
`packaging/docker/README.md`.

| Item | Result |
|------|--------|
| `docker build -f packaging/docker/Dockerfile .` (repo root context) | OK — 5 m 40 s cold build, image 13.6 MB |
| Binary in image | `hardener 1.2.2`, static-pie, stripped |
| Documented scan (`--pid=host`, `/etc` `/var/log` `/usr/lib` read-only, `scan --format json`) | Exit 0, valid JSON, 19 findings |
| Same scan as `--user 1000:1000` | Identical to the root-in-container run (19 findings, same IDs) |
| Native run of the identical binary (extracted from image, non-root host user) | 20 findings |
| Scan with additional `-v /boot:/boot:ro -v /root:/root:ro` | 21 findings (= native 20 + audit degradation below) |
| `report --framework cis` in-container | Exit 0 — 44 controls: 26 pass, 12 fail, 6 manual review |

**Finding-ID delta, container vs native (same binary, so the delta isolates
the container environment — exactly 3 IDs differ):**

- `permissions-hardening`: `perm--root` (0750) and `perm--boot` (0755) are
  absent in-container because `/root` and `/boot` sit outside the documented
  mounts; mounting them read-only restores both findings.
- `audit-hardening`: the container adds `audit_not_installed` because it
  cannot see the host's service manager (auditd is running on the host) — the
  documented tool-unavailable degradation, to be read as *unverifiable
  in-container*, not as host truth.
- Every other finding ID is identical (kernel 4, mac 1, pam 10, ssh 3,
  firewall 0, services 0).

Remote `--ssh` operations are unavailable in the image (no ssh client binary).

---

## v1.1.0 Re-validation (2026-06-28)

The v1.1.0 musl static binary (`hardener 1.1.0`, ~13.6 MB, `static-pie`) was run
through the full CLI suite (`sudo ./scripts/run-cross-distro-tests.sh --apply`)
across all five containers. The GUI/Playwright suite was **subsequently re-run and
is green on all five distros** (113 tests across 9 specs, 2026-06-29 — adds fleet,
fleet-apply, remote, and scheduler coverage).

### Result (final, all harness fixes applied)

| Distro | Total | Pass | Fail | Skip | Exit |
|--------|-------|------|------|------|------|
| arch | 127 | 127 | 0 | 6 | 0 |
| debian | 127 | 127 | 0 | 6 | 0 |
| fedora | 127 | 127 | 0 | 6 | 0 |
| rhel (Rocky 9) | 127 | 127 | 0 | 6 | 0 |
| opensuse | 127 | 127 | 0 | 6 | 0 |

### Failure analysis — no product regressions

The validation ran in two passes; every failure was triaged directly against the
v1.1.0 binary, which emits all expected output correctly.

**Pass 1 — stale test/doc drift (fixed).** `daemon status` failed on all 5 distros
because the suite (and the README) used the pre-v1.1.0 positional form
`daemon status 5`; v1.1.0 renamed it to `-l, --limit <N>`, so the old form errors
(`unexpected argument '5'`, exit 2). Fixed both suite invocations to `--limit 5`
and corrected the README. **Confirmed:** every `daemon status` test passes on all
5 distros.

**Pass 2 — intermittent JSON-grep flake (resolved).** After the daemon fix, some
structure checks intermittently failed to find a field that was demonstrably present
— `"plugin_id"` (`--format json scan`), `report_framework` (`report --report-format
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

**Net:** both harness issues are fixed; the full suite is repeatably **125/125 on all
five distributions** (confirmed by a clean back-to-back single-distro and full run).
A self-diagnosing `diag:` line (exit/bytes/head) remains in `run_test_output`'s
failure path so any future capture anomaly is debuggable from the host log in one run.

---

## Automated Cross-Distro Testing

All validation results in this document are produced by a fully automated test runner. A single command executes 127 tests across all 5 distributions in sequence, collecting pass/fail/skip results and producing a summary table.

### Running the Tests

```bash
# Build the musl static binary first
cargo build --release --target x86_64-unknown-linux-musl -p hardener-cli
cp target/x86_64-unknown-linux-musl/release/hardener target/release/hardener

# Run the full cross-distro validation (requires root for systemd-nspawn)
sudo ./scripts/run-cross-distro-tests.sh --apply
```

The `--apply` flag gates destructive tests (sections 13-16, 23) that modify system state inside containers. Without this flag, those sections are skipped entirely.

### Test Infrastructure

- **Execution:** All tests run via `systemd-nspawn --pipe` (non-interactive, no boot or login required)
- **Binary:** Single musl-linked static binary (~13MB) deployed to all containers
- **Safety:** 3-layer host protection:
  1. `systemd-nspawn` container isolation (filesystem, PID, network namespace)
  2. Container detection hard-exit in the hardener binary itself
  3. `--apply` flag gating for destructive operations
- **Container awareness:** Tests that cannot function inside containers are automatically categorised as SKIP rather than FAIL

### Expected Container Skips (6 per distro)

Every distribution skips exactly 6 tests due to inherent container limitations:

| # | Test | Reason |
|---|------|--------|
| 1 | Daemon start | Blocking command that would hang the test runner |
| 2 | Systemd install | No full systemd init (PID 1) in nspawn |
| 3 | Systemd status after install | Depends on systemd install |
| 4 | Systemd uninstall | Depends on systemd install |
| 5 | Apply audit-hardening | No kernel audit subsystem available in container |
| 6 | Apply mac-hardening | No SELinux/AppArmor kernel modules in container |

These skips are deterministic and identical across all 5 distributions. They do not indicate any deficiency in the hardener -- these subsystems are simply unavailable inside unprivileged containers.

### Container Setup

| Distro | Container Name | Created With | Base Packages |
|--------|---------------|-------------|---------------|
| Arch Linux | hardener-test | pacstrap | base, openssh, audit, ufw, nftables |
| Debian 12 | hardener-test-debian | debootstrap | systemd, openssh-server, auditd, ufw, nftables |
| Fedora 41 | hardener-test-fedora | dnf bootstrap | basesystem, openssh-server, audit, firewalld, nftables |
| Rocky Linux 9 | hardener-test-rhel | podman export | openssh-server, audit, firewalld, nftables |
| openSUSE Leap 15.6 | hardener-test-opensuse | zypper bootstrap | patterns-base-minimal_base, openssh-server, audit, firewalld, nftables |

All containers have: root/test, testuser/test (with passwordless sudo), and firewall tooling installed.

---

## Test Categories (26 Sections, 127 Tests)

| Section | Name | Tests | Description |
|---------|------|-------|-------------|
| 1 | Basic Commands | varies | --version, --help, all subcommand help |
| 2 | Scan All Plugins | 8 | Individual scan for all 8 plugins |
| 3 | Scan Filters | varies | All 5 severity levels, --audit, --compliance, --exit-code |
| 4 | Scan Output Formats | 4 | text, json, csv, html |
| 5 | Reports All Frameworks | 7 | cis, stig, nist, pcidss, hipaa, gdpr, iso27001 |
| 6 | Reports All Scenarios | 7 | server, workstation, government, healthcare, financial, gdpr, all |
| 7 | Report Output Formats | varies | text, json, csv, html, pdf (all frameworks) |
| 8 | Dry-Run All Plugins | 8 | --dry-run for all 8 plugins |
| 9 | Checkpoint Operations | varies | list, create, show, delete |
| 10 | Daemon Commands | varies | status, run-once |
| 11 | History Commands | 3 | list, show, export |
| 12 | Systemd Commands | varies | generate, install, status, uninstall |
| 13 | Apply Kernel | varies | Apply kernel hardening + verify changes |
| 14 | Apply Other Plugins | varies | Apply remaining plugins individually |
| 15 | Apply --all | 1 | Apply all plugins at once |
| 16 | Rollback | 1 | Rollback to checkpoint, verify restoration |
| 17 | Global --format Flag | 3 | Test global format flag with various commands |
| 18 | Error Handling | varies | Invalid plugin, framework, checkpoint ID |
| 19 | Post-Apply Verification | 2 | Final scan + compliance report |
| 20 | Scan History Persistence | 3 | scan -> history list verification |
| 21 | History Filtering | 3 | --limit, --status filters |
| 22 | Plugin Filter Combinations | 4 | Short names, mixed, multi-plugin |
| 23 | Per-Plugin Lifecycle | varies | Apply -> verify -> rollback per plugin (gated behind --apply) |
| 24 | Config File Loading | 2 | Valid/invalid config file |
| 25 | Report Combinations | 2 | Framework + scenario + format combos |
| 26 | Flag Combinations | 3 | --quiet + --format, --audit + --format, multi-flag |

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
| Audit Reload | augenrules --load | augenrules --load | augenrules --load | augenrules --load |

---

## Reproducing These Results

To reproduce the full cross-distro validation from scratch:

1. **Set up containers** -- Each distro has a creation script under `scripts/`:
   - `scripts/create-debian-container.sh`
   - `scripts/create-fedora-container.sh`
   - `scripts/create-opensuse-container.sh`
   - `scripts/create-rhel-container.sh` (Rocky Linux 9 via podman export)

2. **Build the musl static binary**:
   ```bash
   cargo build --release --target x86_64-unknown-linux-musl -p hardener-cli
   cp target/x86_64-unknown-linux-musl/release/hardener target/release/hardener
   ```

3. **Run the cross-distro test suite**:
   ```bash
   sudo ./scripts/run-cross-distro-tests.sh --apply
   ```

4. **Review results** -- The runner outputs a summary table to stdout and per-distro logs under the project directory.

---

## GUI Testing (Web UI -- Playwright)

In addition to CLI testing, the Web UI is validated with Playwright across all 5 distributions.

### Summary

| Distribution | Family | Version | Test Date | Tests | Pass | Fail | Status |
|--------------|--------|---------|-----------|-------|------|------|--------|
| Arch Linux | Arch | Rolling | 2026-02-23 | 84 | 84 | 0 | VALIDATED |
| Debian | Debian | 12 (Bookworm) | 2026-02-23 | 84 | 84 | 0 | VALIDATED |
| Fedora | Red Hat | 41 | 2026-02-23 | 84 | 84 | 0 | VALIDATED |
| Rocky Linux | Red Hat | 9 | 2026-02-23 | 84 | 84 | 0 | VALIDATED |
| openSUSE | SUSE | Leap 15.6 | 2026-02-23 | 84 | 84 | 0 | VALIDATED |

### Test Infrastructure

- **Virtual Display**: Xvfb (X virtual framebuffer) provides a headless display inside containers
- **SPA Server**: `gui-tests/spa-server.py` -- Python HTTP server on port 8787 with client-side routing support (all non-file paths return `index.html`)
- **Test Index Generation**: `scripts/gui-test-inner.sh` dynamically generates the served `index.html` at test-time by reading `dist/index.html`, stripping SRI `integrity` attributes, and injecting `<script src="/tauri-mock.js"></script>` before the first `<script type="module">` tag
- **Tauri IPC Mock**: `gui-tests/tauri-mock.js` -- JavaScript mock of `window.__TAURI__` injected before WASM loads, covering 28 IPC commands: `run_scan`, `run_scan_filtered`, `run_scan_with_options`, `get_latest_scan`, `run_apply`, `run_apply_dry_run`, `get_checkpoints`, `create_checkpoint`, `delete_checkpoint`, `run_rollback`, `generate_compliance_report`, `export_report`, `export_compliance_report`, `get_scan_history`, `get_scan_session`, `list_plugins`, `get_checkpoint_detail`, `list_remote_hosts`, `save_remote_host`, `delete_remote_host`, `connect_remote`, `disconnect_remote`, `run_remote_scan`, `get_scheduler_config`, `save_scheduler_config`, `test_notification`, `validate_config`, `pick_config_file`
- **Browser**: System Chromium auto-detected per distribution (no bundled browser)
- **Test Runner**: Playwright (npm) with `gui-tests/playwright.config.js`

### Test Categories (7 Categories, 84 Tests)

| Category | Test IDs | Tests | Description |
|----------|----------|-------|-------------|
| Dashboard | T-DASH-01..09 | 9 | Score display, scan trigger, navigation, activity feed |
| Findings | T-FIND-01..10 | 10 | Scan, table rendering, detail panel, finding count |
| Compliance | T-COMP-01..08 | 8 | Framework selection, report generation, score colours |
| Configure | T-CONF-01..10 | 10 | Profiles, plugin toggles, preview, cancel |
| History | T-HIST-01..06 | 6 | Checkpoints, rollback, apply results |
| Themes | T-THEME-01..07 | 7 | All 6 themes verified (the theme spec dynamically generates 30 additional screenshot tests: 5 states x 6 themes, bringing the suite total to 84) |
| Errors | T-ERR-01..04 | 4 | Scan/apply/checkpoint errors, dismiss |

### Per-Distro Notes

| Distribution | Chromium Path | Notes |
|--------------|--------------|-------|
| Arch Linux | `/usr/bin/chromium` | Standard package |
| Debian 12 | `/usr/bin/chromium` | Standard package |
| Fedora 41 | `/usr/lib64/chromium-browser/headless_shell` | Uses `chromium-headless` package |
| Rocky Linux 9 | `/usr/bin/chromium-browser` | Requires EPEL + CRB repos, Node.js 20 module |
| openSUSE Leap 15.6 | `/usr/bin/chromium` | Requires `--gpg-auto-import-keys` for zypper + specific lib package names |

### Running GUI Tests

```bash
# Build the WASM frontend first
cd crates/hardener-ui && trunk build --release && cd ../..

# Run GUI tests across all 5 distributions
sudo ./scripts/run-gui-tests.sh

# Or via the cross-distro runner with --gui flag
sudo ./scripts/run-cross-distro-tests.sh --gui
```

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

**Last Updated:** 2026-07-17
