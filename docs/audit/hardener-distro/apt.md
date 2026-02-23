# hardener-distro::package::apt
**File:** `crates/hardener-distro/src/package/apt.rs` | **Lines:** 184

## Purpose
APT package manager backend for Debian/Ubuntu — install, remove, list, security updates.

## Dependencies
- Imports from: `super::{Package, PackageManager}`, `hardener_common::error`
- Used by: `DistributionAdapter` when `DistroFamily::Debian`

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `AptPackageManager` | struct | Unit struct |
| impl `PackageManager` | trait impl | All 6 trait methods |

## Data Flow
- Install: validate → `apt-get install -y <pkgs>`
- Remove: **no validation** → `apt-get remove -y <pkgs>`
- List: `dpkg-query -W` → tab-split → `Vec<Package>`
- Security: `apt-get upgrade --dry-run` → parse `Inst` lines for `-security`

## Flags
- **SECURITY:** `remove()` skips `validate_package_names()` — injection vector.
- **SECURITY:** `is_installed()` doesn't validate package name input.
- **DUPLICATION:** `execute_dpkg_query` reimplements `execute_command` pattern.
