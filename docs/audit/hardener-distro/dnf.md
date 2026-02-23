# hardener-distro::package::dnf
**File:** `crates/hardener-distro/src/package/dnf.rs` | **Lines:** 144

## Purpose
DNF package manager backend for Fedora/RHEL — install, remove, list via RPM, security updates.

## Dependencies
- Imports from: `super::{Package, PackageManager, execute_command, parse_rpm_package_list}`
- Used by: `DistributionAdapter` when `DistroFamily::RedHat`

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `DnfPackageManager` | struct | Unit struct |
| impl `PackageManager` | trait impl | All 6 trait methods |

## Data Flow
- Install/remove: validate → `dnf -y install/remove <pkgs>`
- List: `rpm -qa --queryformat` → `parse_rpm_package_list()`
- Security: `dnf updateinfo list security` → parse advisory lines

## Flags
- **SECURITY:** `is_installed()` doesn't validate package name (passes directly to `rpm -q`).
