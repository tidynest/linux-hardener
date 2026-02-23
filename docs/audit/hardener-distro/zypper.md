# hardener-distro::package::zypper
**File:** `crates/hardener-distro/src/package/zypper.rs` | **Lines:** 132

## Purpose
Zypper package manager backend for SUSE — install, remove, list via RPM, security patches.

## Dependencies
- Imports from: `super::{Package, PackageManager, execute_command, parse_rpm_package_list}`
- Used by: `DistributionAdapter` when `DistroFamily::Suse`

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `ZypperPackageManager` | struct | Unit struct |
| impl `PackageManager` | trait impl | All 6 trait methods |

## Data Flow
- Install/remove: validate → `zypper --non-interactive install/remove <pkgs>`
- List: `rpm -qa --queryformat` → `parse_rpm_package_list()`
- Security: `zypper list-patches --category security` → parse pipe-delimited table

## Flags
- **SECURITY:** `is_installed()` doesn't validate package name (passes directly to `rpm -q`).
