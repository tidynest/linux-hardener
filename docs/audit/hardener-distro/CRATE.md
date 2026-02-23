# hardener-distro — Crate Audit

**Crate:** `hardener-distro` | **Files:** 7 | **Lines:** 1,071

## Purpose
Distribution detection and package manager abstraction — unified interface for APT, DNF, Pacman, Zypper.

## Architecture

```
lib.rs                 (DistroFamily, Distribution::detect())
├── adapter.rs         (DistributionAdapter trait)
└── package/
    ├── mod.rs         (PackageManager trait, validation, shared utils)
    ├── apt.rs         (Debian/Ubuntu: dpkg-query + apt-get)
    ├── dnf.rs         (Fedora/RHEL: rpm + dnf)
    ├── pacman.rs      (Arch: pacman)
    └── zypper.rs      (SUSE: rpm + zypper)
```

## Inter-Module Data Flow

```
/etc/os-release → Distribution::detect() → DistroFamily
                                             ├── Debian  → AptPackageManager
                                             ├── RedHat  → DnfPackageManager
                                             ├── Arch    → PacmanPackageManager
                                             └── Suse    → ZypperPackageManager

Caller → validate_package_name() → execute_command(pkg_mgr, args) → parse → Vec<Package>
```

## Security Model

All package operations pass through `validate_package_name()` before reaching subprocess calls.
The validation blocks command injection characters (`;`, `|`, `$`, spaces, etc.) per distro family rules.

## Audit Summary

| Metric | Count |
|--------|-------|
| Fixes applied | 6 |
| Design flags deferred | 3 |
| Production unwraps removed | 0 (none existed) |
| Tests passing | 400 |

## Fixes Applied

| # | File | Fix |
|---|------|-----|
| 1 | apt.rs | `remove()`: added missing `validate_package_names()` (was only backend without it) |
| 2 | apt.rs | `is_installed()`: added `validate_package_name()` |
| 3 | dnf.rs | `is_installed()`: added `validate_package_name()` |
| 4 | zypper.rs | `is_installed()`: added `validate_package_name()` |
| 5 | pacman.rs | `is_installed()`: added `validate_package_name()` |
| 6 | lib.rs | Error message: "Missing config field" → "Missing os-release field" |

## Design Flags (Deferred)

| # | File | Issue |
|---|------|-------|
| D1 | package/mod.rs | `remove` param `package_name` should be `packages` — trait signature change |
| D2 | lib.rs | `test_family_mapping` outside `mod tests {}` block |
| D3 | apt.rs | `execute_dpkg_query` duplicates `execute_command` pattern |
