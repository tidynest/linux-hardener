# hardener-compliance::frameworks::pci
**File:** `crates/hardener-compliance/src/frameworks/pci.rs` | **Lines:** 177

## Purpose
Defines PCI-DSS v4.0 control mappings relevant to Linux system hardening.

## Dependencies
- Imports from: `hardener_common::types::{ComplianceFramework, ComplianceMapping}`
- Used by: `generator.rs` via `frameworks::get_controls()`

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `get_controls()` | fn | Returns `Vec<ComplianceMapping>` with 22 PCI-DSS controls |

## Coverage
| Section | Controls |
|---------|----------|
| Network Security Controls | 3 (Req 1) |
| Secure Configurations | 4 (Req 2) |
| Protect from Malware | 1 (Req 5) |
| Restrict Access | 2 (Req 7) |
| Identify and Authenticate | 8 (Req 8) |
| Log and Monitor | 4 (Req 10) |

## Fixes Applied
- Typo: `"notused"` → `"not used"` in control 2.2.5 title.

## Flags
None. Pure data, no logic.
