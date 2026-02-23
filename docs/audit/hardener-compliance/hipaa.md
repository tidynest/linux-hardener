# hardener-compliance::frameworks::hipaa
**File:** `crates/hardener-compliance/src/frameworks/hipaa.rs` | **Lines:** 118

## Purpose
Defines HIPAA Security Rule (45 CFR 164) control mappings for Linux systems.

## Dependencies
- Imports from: `hardener_common::types::{ComplianceFramework, ComplianceMapping}`
- Used by: `generator.rs` via `frameworks::get_controls()`

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `get_controls()` | fn | Returns `Vec<ComplianceMapping>` with 14 HIPAA controls |

## Coverage
| Section | Controls |
|---------|----------|
| Access Control (164.312(a)) | 5 |
| Audit Controls (164.312(b)) | 1 |
| Integrity (164.312(c)) | 2 |
| Authentication (164.312(d)) | 1 |
| Transmission Security (164.312(e)) | 3 |
| Administrative Safeguards (164.308(a)) | 2 |

## Flags
None. Pure data, no logic.
