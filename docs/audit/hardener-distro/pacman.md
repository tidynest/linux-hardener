# hardener-distro::package::pacman
**File:** `crates/hardener-distro/src/package/pacman.rs` | **Lines:** 112

## Purpose
Pacman package manager backend for Arch Linux — install, remove, list, no security-specific updates.

## Dependencies
- Imports from: `super::{Package, PackageManager}`
- Used by: `DistributionAdapter` when `DistroFamily::Arch`

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `PacmanPackageManager` | struct | Unit struct |
| impl `PackageManager` | trait impl | All 6 trait methods |

## Data Flow
- Install/remove: validate → `pacman -S/-R --noconfirm <pkgs>`
- List: `pacman -Q` → whitespace-split
- Security: returns empty (rolling release, no separate security updates)

## Flags
- **SECURITY:** `is_installed()` doesn't validate package name (passes directly to `pacman -Q`).
