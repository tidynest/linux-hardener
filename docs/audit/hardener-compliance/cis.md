# hardener-compliance::frameworks::cis
**File:** `crates/hardener-compliance/src/frameworks/cis.rs` | **Lines:** 279

## Purpose
Defines CIS Benchmark control mappings for Distribution Independent Linux v2.0.

## Dependencies
- Imports from: `hardener_common::types::{ComplianceFramework, ComplianceMapping}`
- Used by: `generator.rs` via `frameworks::get_controls()`

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `get_controls()` | fn | Returns `Vec<ComplianceMapping>` with 34 CIS controls |

## Data Flow
Called once during report generation → returns static list → matched against scan findings.

## Coverage
| Section | Controls | CIS IDs |
|---------|----------|---------|
| Initial Setup | 4 | 1.5.1-1.5.4 |
| Network Configuration | 8 | 3.2.x, 3.4.x |
| Logging and Auditing | 3 | 4.1.x |
| Access Control | 10 | 5.1-5.3 (SSH, PAM, cron) |
| System Maintenance | 4 | 6.1.x (file permissions) |
| Services | 4 | 2.1-2.2 |
| Mandatory Access Control | 4 | 1.6.x (SELinux/AppArmor) |

## Flags
None. Pure data, no logic.
