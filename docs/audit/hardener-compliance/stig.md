# hardener-compliance::frameworks::stig
**File:** `crates/hardener-compliance/src/frameworks/stig.rs` | **Lines:** 156

## Purpose
Defines DISA STIG (RHEL 8/9) control mappings for Linux system hardening.

## Dependencies
- Imports from: `hardener_common::types::{ComplianceFramework, ComplianceMapping}`
- Used by: `generator.rs` via `frameworks::get_controls()`

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `get_controls()` | fn | Returns `Vec<ComplianceMapping>` with 20 STIG controls |

## Coverage
| Section | Controls |
|---------|----------|
| Kernel Security | 5 (V-230280–V-230284) |
| Network Security | 3 (V-230288–V-230289, V-230505) |
| SSH Configuration | 5 (V-230296–V-230300) |
| Auditing | 2 (V-230386, V-230390) |
| Mandatory Access Control | 2 (V-230223–V-230224) |
| Authentication | 3 (V-230356–V-230358) |

## Flags
None. Pure data, no logic.
