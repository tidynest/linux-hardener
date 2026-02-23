# hardener-compliance::frameworks::nist
**File:** `crates/hardener-compliance/src/frameworks/nist.rs` | **Lines:** 151

## Purpose
Defines NIST 800-53 Rev 5 control mappings for Linux system hardening.

## Dependencies
- Imports from: `hardener_common::types::{ComplianceFramework, ComplianceMapping}`
- Used by: `generator.rs` via `frameworks::get_controls()`

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `get_controls()` | fn | Returns `Vec<ComplianceMapping>` with 20 NIST controls |

## Coverage
| Section | Controls |
|---------|----------|
| Access Control (AC) | 6 (AC-3 through AC-17) |
| Audit and Accountability (AU) | 4 (AU-2 through AU-12) |
| Configuration Management (CM) | 2 (CM-6, CM-7) |
| Identification and Authentication (IA) | 2 (IA-2, IA-5) |
| System and Communications Protection (SC) | 4 (SC-5 through SC-23) |
| System and Information Integrity (SI) | 2 (SI-2, SI-16) |

## Flags
None. Pure data, no logic.
