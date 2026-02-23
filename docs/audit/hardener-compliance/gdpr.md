# hardener-compliance::frameworks::gdpr
**File:** `crates/hardener-compliance/src/frameworks/gdpr.rs` | **Lines:** 105

## Purpose
Defines GDPR Article 32 (Security of Processing) control mappings.

## Dependencies
- Imports from: `hardener_common::types::{ComplianceFramework, ComplianceMapping}`
- Used by: `generator.rs` via `frameworks::get_controls()`

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `get_controls()` | fn | Returns `Vec<ComplianceMapping>` with 12 GDPR controls |

## Coverage
| Section | Controls |
|---------|----------|
| Security of Processing (Art.32(1)) | 7 (encryption, CIA, resilience, restore, testing) |
| Technical Measures (derived) | 5 (AC, audit, network, auth, hardening) |

## Flags
None. Pure data, no logic.
