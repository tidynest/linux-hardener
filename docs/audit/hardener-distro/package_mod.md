# hardener-distro::package
**File:** `crates/hardener-distro/src/package/mod.rs` | **Lines:** 240

## Purpose
Package manager abstraction — trait, validation, shared utilities for APT/DNF/Pacman/Zypper.

## Dependencies
- Imports from: `hardener_common::error`
- Used by: all 4 package backends, `adapter.rs`, `hardener-plugins::services`

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `Package` | struct | name, version, arch, is_security_update |
| `PackageNameRules` | enum | Debian, Rpm, Arch — char validation rulesets |
| `validate_package_name(name, rules)` | fn | Security: blocks command injection chars |
| `validate_package_names(packages, rules)` | fn | Batch validation |
| `run_package_command(cmd, args)` | fn | Shared subprocess runner with error handling |
| `rpm_is_installed(name, executor)` | fn | RPM query helper shared by DNF + Zypper |
| `parse_rpm_package_list(output)` | fn | Tab-delimited RPM output → `Vec<Package>` |
| `PackageManager` | trait | update, install, remove, list_installed, is_installed, security_updates |
| `Apt/Dnf/Pacman/ZypperPackageManager` | re-exports | Concrete implementations |

## Data Flow
Caller → `validate_package_name()` → `execute_command(pkg_mgr, args)` → parse stdout → `Vec<Package>`

## Flags
- **INCONSISTENCY:** `remove(&self, package_name: &[&str])` — param should be `packages` to match `install` signature.
