# hardener-distro::lib
**File:** `crates/hardener-distro/src/lib.rs` | **Lines:** 185

## Purpose
Crate root — distro detection via `/etc/os-release`, distribution family enum, re-exports.

## Dependencies
- Imports from: `hardener_common::error`
- Used by: `hardener-plugins` (distro-aware behaviour), `hardener-cli`

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `DistroFamily` | enum | Debian, RedHat, Arch, Suse |
| `Distribution` | struct | family, name, version, codename |
| `Distribution::detect()` | fn | Parse `/etc/os-release` → `Distribution` |
| `DistributionAdapter` | re-export | From adapter module |

## Data Flow
`/etc/os-release` → `read_os_release()` → HashMap → `extract_field()` → `map_to_family()` → `Distribution`

## Internal Functions
| Function | Lines | Description |
|----------|-------|-------------|
| `read_os_release` | 67-84 | Read + parse key=value file |
| `extract_field` | 87-97 | HashMap lookup with error |
| `map_to_family` | 100-119 | ID string → DistroFamily enum |

## Flags
- **STYLE:** `test_family_mapping` (line 149) is outside `mod tests {}` block.
- **MISLEADING:** Error at line 93 says "Missing config field" — should say "Missing os-release field".
