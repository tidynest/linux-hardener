# hardener-distro::adapter
**File:** `crates/hardener-distro/src/adapter.rs` | **Lines:** 107

## Purpose
Distribution adapter trait — common interface for distro-specific behaviour.

## Dependencies
- Imports from: `crate::{Distribution, DistroFamily}`
- Used by: potentially plugin code for distro-specific logic

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `DistributionAdapter` | trait | `distribution()` + default `family()` |

## Data Flow
`Distribution` → `DistributionAdapter::distribution()` → `family()` delegates to struct field

## Flags
None — clean, minimal trait with thorough tests.
